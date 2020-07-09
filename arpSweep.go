package main

import (
	"arpSweep/selfArp"
	"flag"
	"fmt"
	"log"
	"os"
)

var iface string

func main() {
	// allow non root user to execute by compare with euid
	if os.Geteuid() != 0 {
		log.Print("goscan must run as root.")
	}
	flag.StringVar(&iface, "I", "", "Network interface name")
	flag.Parse()

	// 初始化 data

	Worker(iface)
}

func Worker(iface string){
	ArpHandle := selfArp.NewArpHandle(iface)
	defer ArpHandle.Close()
	ArpHandle.Scanner()
	fmt.Println("发现存活主机:", len(ArpHandle.Rawdict.Dictionary))
	for ip,mac := range ArpHandle.Rawdict.Dictionary {
		fmt.Println(ip,mac)
	}
}

