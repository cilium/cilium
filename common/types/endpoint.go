package types

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/noironetworks/cilium-net/bpf/policymap"
)

const (
	CiliumPreffix = "cilium://"
	DockerPreffix = "docker://"
)

type EPPortMap struct {
	From  uint16 `json:"from"`
	To    uint16 `json:"to"`
	Proto uint8  `json:"proto"`
}

type Consumer struct {
	Decision ConsumableDecision
}

type Endpoint struct {
	ID            string               `json:"id"`
	DockerID      string               `json:"docker-id"`
	LxcMAC        net.HardwareAddr     `json:"lxc-MAC"`
	LxcIP         net.IP               `json:"lxc-IP"`
	NodeMAC       net.HardwareAddr     `json:"node-MAC"`
	Ifname        string               `json:"interface-Name"`
	IfIndex       int                  `json:"ifindex"`
	NodeIP        net.IP               `json:"node-IP"`
	DockerNetwork string               `json:"docker-network"`
	SecLabel      uint32               `json:"security-label"`
	PortMap       []EPPortMap          `json:"port-mapping"`
	PolicyMap     *policymap.PolicyMap `json:"-"`
	Consumers     map[string]Consumer  `json:"consumers"`
}

func (e *Endpoint) Consumer(id int) *Consumer {
	if val, ok := e.Consumers[strconv.Itoa(id)]; ok {
		return &val
	} else {
		return nil
	}
}

func (e *Endpoint) AllowConsumer(id int) {
	if consumer := e.Consumer(id); consumer != nil {
		consumer.Decision = ACCEPT
	} else {
		if e.Consumers == nil {
			e.Consumers = make(map[string]Consumer)
		}

		n := strconv.Itoa(id)
		e.Consumers[n] = Consumer{Decision: ACCEPT}
	}
}

func (e *Endpoint) AllowsSecLabel(id int) bool {
	if c := e.Consumer(id); c != nil {
		if c.Decision == ACCEPT {
			return true
		}
	}

	return false
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
	e.ID = CalculateID(e.LxcIP)
}

func CalculateID(ip net.IP) string {
	if len(ip) == net.IPv6len {
		return strconv.Itoa(int(binary.BigEndian.Uint16(ip[14:])))
	}
	return ""
}
