package main

import (
	"arpSweep/selfArp"
	"flag"
	"fmt"
	"log"
	"os"
)

var iface string
var mod int

func main() {
	// allow non root user to execute by compare with euid
	if os.Geteuid() != 0 {
		log.Print("goscan must run as root.")
	}
	flag.StringVar(&iface, "I", "", "Network interface name")
	flag.IntVar(&mod, "mod", 1, "1 : 存活主机探测   2:混杂模式主机探测")
	flag.Parse()

	// 初始化 data

	Worker(iface,mod)
}

func Worker(iface string,mod int){
	ArpHandle := selfArp.NewArpHandle(iface,mod)
	defer ArpHandle.Close()
	ArpHandle.Scanner()
	if mod == 1 {
		fmt.Println("发现存活主机:", len(ArpHandle.Rawdict.Dictionary))
	}else{
		fmt.Println("发现混杂模式主机:", len(ArpHandle.Rawdict.Dictionary))
	}

	for ip,mac := range ArpHandle.Rawdict.Dictionary {
		fmt.Println(ip,mac)
	}
}

