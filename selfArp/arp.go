package selfArp

import (
	"arpSweep/utils/selfIp"
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"sync"
	"time"
)

// 发送arp包
// ip 目标IP地址
const (
	// 3秒的计时器
	START = "start"
	END = "end"
)

type ArpHandle struct {
	handle *pcap.Handle
	iface	string
	Rawdict *ArpDictionary  //原始字典
	dowork chan string  //收集阶段使用
	ipNet *net.IPNet
	localHaddr net.HardwareAddr  // 本机的mac地址，发以太网包需要用到
	ctx context.Context
	cancel context.CancelFunc
	tTicker *time.Ticker
	mod  int
}

func NewArpHandle(iface string,mod int)(*ArpHandle){
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ArpHandle{
		handle: handle,
		iface: iface,
		Rawdict: &ArpDictionary{
			Dictionary:make(map[string]Info),
			DictionaryMutex:new(sync.RWMutex),
		},
		dowork: make(chan string),
		ctx: ctx,
		cancel: cancel,
		mod:mod,
	}
}

func (self *ArpHandle)Close() {
	self.handle.Close()
}

func (self *ArpHandle)setupNetInfo() {
	var ifs []net.Interface
	var err error
	if self.iface == "" {
		ifs, err = net.Interfaces()
	} else {
		// 已经选择iface
		var it *net.Interface
		it, err = net.InterfaceByName(self.iface)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	if err != nil {
		log.Fatal("无法获取本地网络信息:", err)
	}
	for _, it := range ifs {
		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					self.ipNet = ip
					self.localHaddr = it.HardwareAddr
					self.iface = it.Name
					goto END
				}
			}
		}
	}
END:
	if self.ipNet == nil || len(self.localHaddr) == 0 {
		log.Fatal("无法获取本地网络信息")
	}
}

func (self *ArpHandle)Scanner() {
	self.setupNetInfo()
	go self.ListenARP()
	go self.sendARP()

	//超时
	funcTicker := time.NewTicker(20 * time.Second)
	self.tTicker = time.NewTicker(4 * time.Second)
	for {
		select {
		case <-self.tTicker.C:
			self.cancel()
			goto END
		case <-funcTicker.C:
			log.Println("funcTicker 触发退出")
			self.cancel()
			goto END
		case d := <-self.dowork:
			switch d {
			case START:
				self.tTicker.Stop()
			case END:
				// 接收到新数据，重置2秒的计数器
				self.tTicker = time.NewTicker(2 * time.Second)
			}
		}
	}
END:
}

func (self *ArpHandle)sendARP() {
	// ips 是内网IP地址集合
	ips := selfIp.Table(self.ipNet)
	for _, ip := range ips {
		go self.SendArpPackage(ip)
	}
}

func (self *ArpHandle)SendArpPackage(ip selfIp.IP) {
	srcIp := net.ParseIP(self.ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		log.Fatal("ip 解析出问题")
	}
	// 以太网首部
	// EthernetType 0x0806  ARP
	var DstMAC = net.HardwareAddr{}
	if self.mod == 1 {
		DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	}else{
		DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}
	}

	ether := &layers.Ethernet{
		SrcMAC: self.localHaddr,
		DstMAC: DstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: uint8(6),
		ProtAddressSize: uint8(4),
		Operation: uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress: self.localHaddr,
		SourceProtAddress: srcIp,
		DstHwAddress: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress: dstIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	err := self.handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("发送arp数据包失败..")
	}
}

const (
	RequestARP = 1
	ReplyARP   = 2
)

func (self *ArpHandle)ListenARP() {
	self.handle.SetBPFFilter("arp")
	ps := gopacket.NewPacketSource(self.handle, self.handle.LinkType())
	for {
		select {
		case <-self.ctx.Done():
			return
		case p := <-ps.Packets():
			arpPacket := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			//log.Println(p,"=================",arpPacket.Operation)
			if arpPacket.Operation == ReplyARP {
				mac := net.HardwareAddr(arpPacket.SourceHwAddress)
				self.pushRawdict(selfIp.ParseIP(arpPacket.SourceProtAddress).String(), mac)
			}
		}
	}
}

// 将抓到的数据集加入到data中，同时重置计时器
func (self *ArpHandle)pushRawdict(ip string, mac net.HardwareAddr) {
	// 停止计时器
	self.dowork <- START
	var mu sync.RWMutex
	mu.RLock()
	defer func() {
		// 重置计时器
		self.dowork <- END
		mu.RUnlock()
	}()
	value, ok := self.Rawdict.Get(ip)
	if !ok {
		self.Rawdict.Put(ip,Info{Mac: mac})
		return
	}
	if mac != nil {
		self.Rawdict.Put(ip,value)
	}
	return
}