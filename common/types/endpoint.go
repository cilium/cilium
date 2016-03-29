package types

import (
	"encoding/binary"
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
	Refcnt   int
}

type Endpoint struct {
	ID            string               `json:"id"`
	DockerID      string               `json:"docker-id"`
	LxcMAC        MAC                  `json:"lxc-MAC"`
	LxcIP         net.IP               `json:"lxc-IP"`
	NodeMAC       MAC                  `json:"node-MAC"`
	Ifname        string               `json:"interface-Name"`
	IfIndex       int                  `json:"ifindex"`
	NodeIP        net.IP               `json:"node-IP"`
	DockerNetwork string               `json:"docker-network"`
	SecLabel      uint32               `json:"security-label"`
	PortMap       []EPPortMap          `json:"port-mapping"`
	PolicyMap     *policymap.PolicyMap `json:"-"`
	Consumers     map[string]*Consumer `json:"consumers"`
}

func (e *Endpoint) Consumer(id int) *Consumer {
	if val, ok := e.Consumers[strconv.Itoa(id)]; ok {
		return val
	} else {
		return nil
	}
}

func (e *Endpoint) AllowConsumer(id int) {
	if consumer := e.Consumer(id); consumer != nil {
		consumer.Decision = ACCEPT
		consumer.Refcnt++
	} else {
		if e.Consumers == nil {
			e.Consumers = make(map[string]*Consumer)
		}

		n := strconv.Itoa(id)
		e.Consumers[n] = &Consumer{Decision: ACCEPT, Refcnt: 1}
	}

	if e.PolicyMap != nil {
		log.Debugf("Updating map element %v: allowing %d\n", e, id)
		if err := e.PolicyMap.AllowConsumer(uint32(id)); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	} else {
		log.Warningf("No policy map available, skipping update\n")
	}
}

func (e *Endpoint) BanConsumer(id int) {
	n := strconv.Itoa(id)

	log.Debugf("Baning consumer %d\n", id)

	if c, ok := e.Consumers[n]; ok {
		if c.Refcnt > 1 {
			c.Refcnt--
			return
		}

		delete(e.Consumers, n)
	}

	if e.PolicyMap != nil {
		log.Debugf("Updating map element %v: denying %d\n", e, id)
		if err := e.PolicyMap.DeleteConsumer(uint32(id)); err != nil {
			log.Warningf("Update of policy map failed: %s\n", err)
		}
	} else {
		log.Warningf("No policy map available, skipping udpate\n")
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

func (e *Endpoint) SetID() {
	e.ID = CalculateID(e.LxcIP)
}

func CalculateID(ip net.IP) string {
	if len(ip) == net.IPv6len {
		return strconv.Itoa(int(binary.BigEndian.Uint16(ip[14:])))
	}
	return ""
}

func (e *Endpoint) IPv4Address(v4Range *net.IPNet) *net.IP {
	ip := make(net.IP, len(v4Range.IP))
	copy(ip, v4Range.IP)

	id := e.U16ID()
	ip[2] = byte(id >> 8)
	ip[3] = byte(id & 0xff)

	return &ip
}
