package main

import (
	"net"
)

type endpoint struct {
	ID     string           `json:id`
	lxcMAC net.HardwareAddr `json:lxc-MAC`
	lxcIP  net.IP           `json:lxc-IP`
	ifname string           `json:interface-Name`
	nodeIP net.IP           `json:node-IP`
	secCtx string           `json:sec-Ctx`
}
