package types

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Endpoint struct {
	ID            string           `json:id`
	LxcMAC        net.HardwareAddr `json:lxc-MAC`
	LxcIP         net.IP           `json:lxc-IP`
	Ifname        string           `json:interface-Name`
	NodeIP        net.IP           `json:node-IP`
	SecCtx        string           `json:sec-Ctx`
	DockerNetwork string           `json:docker-network`
}

func (e *Endpoint) SetID() {
	if len(e.LxcIP) == net.IPv6len {
		e.ID = strconv.Itoa(int(binary.BigEndian.Uint16(e.LxcIP[14:])))
	}
}
