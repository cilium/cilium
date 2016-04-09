package types

import (
	"encoding/binary"
	"net"
	"strconv"

	"github.com/noironetworks/cilium-net/bpf/policymap"
)

const (
	// Endpoint prefixes

	// CiliumPreffix is used to distinguish cilium IDs between different ID types.
	CiliumPreffix = "cilium://"
	// DockerPreffix is used to distinguish docker IDs between different ID types.
	DockerPreffix = "docker://"
)

// EPPortMap is the port mapping representation for a particular endpoint.
type EPPortMap struct {
	From  uint16 `json:"from"`
	To    uint16 `json:"to"`
	Proto uint8  `json:"proto"`
}

// Consumer represents a consumer that can consume an endpoint.
type Consumer struct {
	// Decision is the decision referent where this consumer can, or not, consume this
	// endpoint.
	Decision ConsumableDecision
	// RefCnt contains the number of endpoints that share the same consumption's
	// policy.
	Refcnt int
}

// Endpoint contains all the details for a particular LXC and the host interface to where
// is connected to.
type Endpoint struct {
	ID            string `json:"id"`              // Endpoint ID.
	DockerID      string `json:"docker-id"`       // Docker ID.
	DockerNetwork string `json:"docker-network"`  // Docker network ID.
	Ifname        string `json:"interface-name"`  // Container's interface name.
	LxcMAC        MAC    `json:"lxc-mac"`         // Container MAC address.
	LxcIP         net.IP `json:"lxc-ip"`          // Container IPv6 address.
	IfIndex       int    `json:"interface-index"` // Host's interface index.
	NodeMAC       MAC    `json:"node-mac"`        // Node MAC address.
	NodeIP        net.IP `json:"node-ip"`         // Node IPv6 address.
	// TODO: change uint32 to uint16 since we only support 0xffff labels
	SecLabel  uint32               `json:"security-label"` // Security Label set to this endpoint.
	PortMap   []EPPortMap          `json:"port-mapping"`   // Port mapping used for this endpoint.
	PolicyMap *policymap.PolicyMap `json:"-"`              // Policy Map in use for this endpoint.
	// TODO: ask tgraf why the key is a string and not an int
	Consumers map[string]*Consumer `json:"consumers"` // List of consumers that can consume this endpoint.
}

func (e *Endpoint) Consumer(id int) *Consumer {
	if val, ok := e.Consumers[strconv.Itoa(id)]; ok {
		return val
	} else {
		return nil
	}
}

// AllowConsumer allows the consumer that have the same SecLabelID as the given id to
// consume the receiver's endpoint.
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

// BanConsumer bans the consumer that have the same SecLabelID as the given id from
// consuming the receiver's endpoint.
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

// AllowsSecLabel allows the consumer that have the same SecLabelID as the given id to
// consume the receiver's endpoint.
// TODO: compare with AllowConsumer func
func (e *Endpoint) AllowsSecLabel(id int) bool {
	if c := e.Consumer(id); c != nil {
		if c.Decision == ACCEPT {
			return true
		}
	}

	return false
}

// U16ID returns the endpoint's ID has uint16
func (e *Endpoint) U16ID() uint16 {
	n, _ := strconv.ParseUint(e.ID, 10, 16)
	return uint16(n)
}

// SetID sets the endpoint's host local unique ID.
func (e *Endpoint) SetID() {
	e.ID = CalculateID(e.LxcIP)
}

func CalculateID(ip net.IP) string {
	if len(ip) == net.IPv6len {
		return strconv.Itoa(int(binary.BigEndian.Uint16(ip[14:])))
	}
	return ""
}

// IPv4Address returns the TODO: what does this do?
func (e *Endpoint) IPv4Address(v4Range *net.IPNet) *net.IP {
	ip := make(net.IP, len(v4Range.IP))
	copy(ip, v4Range.IP)

	id := e.U16ID()
	ip[2] = byte(id >> 8)
	ip[3] = byte(id & 0xff)

	return &ip
}
