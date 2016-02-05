package types

import (
	"encoding/binary"
	"net"
	"strconv"
)

type PortMap struct {
	From  uint16 `json:from`
	To    uint16 `json:to`
	Proto uint8  `json:proto`
}

type Endpoint struct {
	ID            string           `json:id`
	LxcMAC        net.HardwareAddr `json:lxc-MAC`
	LxcIP         net.IP           `json:lxc-IP`
	NodeMAC       net.HardwareAddr `json:node-MAC`
	Ifname        string           `json:interface-Name`
	NodeIP        net.IP           `json:node-IP`
	SecCtx        string           `json:sec-Ctx`
	DockerNetwork string           `json:docker-network`
	PortMap       []PortMap        `json:port-mapping`
}

func (e *Endpoint) SetID() {
	if len(e.LxcIP) == net.IPv6len {
		e.ID = strconv.Itoa(int(binary.BigEndian.Uint16(e.LxcIP[14:])))
	}
}
