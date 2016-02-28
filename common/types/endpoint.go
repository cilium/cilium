package types

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

type EPPortMap struct {
	From  uint16 `json:"from"`
	To    uint16 `json:"to"`
	Proto uint8  `json:"proto"`
}

type Endpoint struct {
	ID            string           `json:"id"`
	LxcMAC        net.HardwareAddr `json:"lxc-MAC"`
	LxcIP         net.IP           `json:"lxc-IP"`
	NodeMAC       net.HardwareAddr `json:"node-MAC"`
	Ifname        string           `json:"interface-Name"`
	IfIndex       int              `json:"ifindex"`
	NodeIP        net.IP           `json:"node-IP"`
	DockerNetwork string           `json:"docker-network"`
	SecLabel      uint32           `json:"security-label"`
	PortMap       []EPPortMap      `json:"port-mapping"`
}

func (e *Endpoint) U16ID() uint16 {
	n, _ := strconv.ParseUint(e.ID, 10, 16)
	return uint16(n)
}

func (e *Endpoint) U64MAC() (uint64, error) {
	if len(e.LxcMAC) != 6 {
		return 0, fmt.Errorf("Invalid MAC address %s", string(e.LxcMAC))
	}

	return uint64(uint64(e.LxcMAC[5])<<40 |
		uint64(e.LxcMAC[4])<<32 |
		uint64(e.LxcMAC[3])<<24 |
		uint64(e.LxcMAC[2])<<16 |
		uint64(e.LxcMAC[1])<<8 |
		uint64(e.LxcMAC[0])), nil
}

func (e *Endpoint) SetID() {
	if len(e.LxcIP) == net.IPv6len {
		e.ID = strconv.Itoa(int(binary.BigEndian.Uint16(e.LxcIP[14:])))
	}
}
