package netlink

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Nexthop struct {
	ID        uint32
	Blackhole bool
	OIF       uint32
	Gateway   net.IP
	Protocol  RouteProtocol
}

func (h *Nexthop) String() string {
	elems := []string{
		"ID: " + strconv.FormatUint(uint64(h.ID), 10),
		"Blackhole: " + strconv.FormatBool(h.Blackhole),
		"OIF: " + strconv.FormatUint(uint64(h.OIF), 10),
		"Gateway: " + h.Gateway.String(),
		"Protocol: " + h.Protocol.String(),
	}
	return fmt.Sprintf("{%s}", strings.Join(elems, " "))
}
