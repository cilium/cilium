package netlink

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Nexthop group types - reference https://github.com/torvalds/linux/blob/master/include/uapi/linux/nexthop.h
const (
	// NEXTHOP_GRP_TYPE_MPATH is the default multi-path hash threshold group type.
	NEXTHOP_GRP_TYPE_MPATH uint16 = iota

	// NEXTHOP_GRP_TYPE_RES is a resilient nexthop group.
	NEXTHOP_GRP_TYPE_RES
)

// NexthopGroupMember represents one member of a nexthop group.
type NexthopGroupMember struct {
	// ID of an existing nexthop to include in the group.
	ID uint32
	// Relative weight, 1-256. Zero is treated as 1.
	Weight uint16
}

// NexthopResilientGroup contains the configuration for a resilient nexthop group.
type NexthopResilientGroup struct {
	Buckets         uint16
	IdleTimer       uint32
	UnbalancedTimer uint32
	UnbalancedTime  uint64
}

// Nexthop represents a nexthop object.
type Nexthop struct {
	ID        uint32
	Blackhole bool
	OIF       uint32
	Gateway   net.IP
	Protocol  RouteProtocol
	// Group holds nexthop group members for multipath or resilient groups.
	Group          []NexthopGroupMember
	GroupType      uint16
	ResilientGroup *NexthopResilientGroup
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
