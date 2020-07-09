package selfIp

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

type IP uint32
// 根据IP和mask换算内网IP范围
func Table(ipNet *net.IPNet) []IP {
	ip := ipNet.IP.To4()
	fmt.Printf("本机ip: %s", ip)
	var min, max IP
	var data []IP
	for i := 0; i < 4; i++ {
		b := IP(ip[i] & ipNet.Mask[i])
		min += b << ((3 - uint(i)) * 8)
	}
	one, _ := ipNet.Mask.Size()
	max = min | IP(math.Pow(2, float64(32 - one)) - 1)
	fmt.Println("内网IP范围:",min," --- ", max)
	// max 是广播地址，忽略
	// i & 0x000000ff  == 0 是尾段为0的IP，根据RFC的规定，忽略
	for i := min; i < max; i++ {
		if i & 0x000000ff == 0 {
			continue
		}
		data = append(data, i)
	}
	return data
}

// []byte --> IP
func ParseIP(b []byte) IP {
	return IP(IP(b[0]) << 24 + IP(b[1]) << 16 + IP(b[2]) << 8 + IP(b[3]))
}

// string --> IP
func ParseIPString(s string) IP{
	var b []byte
	for _, i := range strings.Split(s, ".") {
		v, _ := strconv.Atoi(i)
		b = append(b, uint8(v))
	}
	return ParseIP(b)
}

// 将 IP(uint32) 转换成 可读性IP字符串
func (ip IP) String() string {
	var bf bytes.Buffer
	for i := 1; i <= 4; i++ {
		bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			bf.WriteByte('.')
		}
	}
	return bf.String()
}