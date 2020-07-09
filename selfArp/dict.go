package selfArp

import (
	"net"
	"sync"
)

type Info struct {
	// IP地址
	Mac      net.HardwareAddr
}

type ArpDictionary struct {
	Dictionary map[string]Info
	DictionaryMutex  *sync.RWMutex
}

func (this *ArpDictionary)Put(key string,value Info) {
	this.DictionaryMutex.Lock()
	this.Dictionary[key] = value
	this.DictionaryMutex.Unlock()
}

func (this *ArpDictionary)Get(key string) (Info,bool) {
	this.DictionaryMutex.RLock()
	defer this.DictionaryMutex.RUnlock()
	value,ok :=this.Dictionary[key]
	return value,ok
}