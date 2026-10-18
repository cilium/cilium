package netlink

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	// sizeofNexthopGroupMember is the size of a single nexthop group member.
	sizeofNexthopGroupMember = 8

	// nexthopResilientGroupUserHz is the userspace clock ticks per second.
	nexthopResilientGroupUserHz = 100
)

// NexthopAdd will add a nexthop to the system.
// Equivalent to: `ip nexthop add $nexthop`
func NexthopAdd(nh *Nexthop) error {
	return pkgHandle().NexthopAdd(nh)
}

// NexthopAdd will add a nexthop to the system.
// Equivalent to: `ip nexthop add $nexthop`
func (h *Handle) NexthopAdd(nh *Nexthop) error {
	flags := unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK
	req := h.newNetlinkRequest(unix.RTM_NEWNEXTHOP, flags)
	if err := prepareNewNexthop(nh, req, &nl.Nhmsg{}); err != nil {
		return err
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// NexthopReplace will replace a nexthop in the system.
// Equivalent to: `ip nexthop replace $nexthop`
func NexthopReplace(nh *Nexthop) error {
	return pkgHandle().NexthopReplace(nh)
}

// NexthopReplace will replace a nexthop in the system.
// Equivalent to: `ip nexthop replace $nexthop`
func (h *Handle) NexthopReplace(nh *Nexthop) error {
	flags := unix.NLM_F_CREATE | unix.NLM_F_REPLACE | unix.NLM_F_ACK
	req := h.newNetlinkRequest(unix.RTM_NEWNEXTHOP, flags)
	if err := prepareNewNexthop(nh, req, &nl.Nhmsg{}); err != nil {
		return err
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// NexthopDel will delete a nexthop from the system.
// Equivalent to: `ip nexthop del $nexthop`
func NexthopDel(nh *Nexthop) error {
	return pkgHandle().NexthopDel(nh)
}

// NexthopDel will delete a nexthop from the system.
// Equivalent to: `ip nexthop del $nexthop`
func (h *Handle) NexthopDel(nh *Nexthop) error {
	req := h.newNetlinkRequest(unix.RTM_DELNEXTHOP, unix.NLM_F_ACK)
	if err := prepareDelNexthop(nh, req, &nl.Nhmsg{}); err != nil {
		return err
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// NexthopList gets a list of nexthop in the system.
// Equivalent to: `ip nexthop show`.
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func NexthopList() ([]Nexthop, error) {
	return pkgHandle().NexthopList()
}

// NexthopList gets a list of nexthop in the system.
// Equivalent to: `ip nexthop show`.
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func (h *Handle) NexthopList() ([]Nexthop, error) {
	req := h.newNetlinkRequest(unix.RTM_GETNEXTHOP, unix.NLM_F_DUMP)

	nhmsg := &nl.Nhmsg{}
	nhmsg.Family = FAMILY_ALL
	req.AddData(nhmsg)

	var (
		parseErr error
		nhs      []Nexthop
	)
	executeErr := req.ExecuteIter(unix.NETLINK_ROUTE, 0, func(m []byte) bool {
		nh, err := parseNhmsg(m)
		if err != nil {
			parseErr = err
			return false
		}
		nhs = append(nhs, *nh)
		return true
	})
	if executeErr != nil && !errors.Is(executeErr, ErrDumpInterrupted) {
		return nil, executeErr
	}
	if parseErr != nil {
		return nil, parseErr
	}
	return nhs, executeErr
}

// Mapping of NHA_* => encode/decode functions. Don't use this map directly.
// Use encodeNexthopAttrs/decodeNexthopAttrs instead.
var nexthopAttrHandlers = map[uint16]struct {
	// encode encodes the corresponding attribute from Nexthop into RtAttr.
	// It should return nil if the attribute is not set.
	encode func(*Nexthop) *nl.RtAttr
	// decode decodes the corresponding attribute from RtAttr into Nexthop
	// It must perform bounds check for the given attribute's data and does
	// nothing if the attribute encoding is invalid.
	decode func(*Nexthop, *nl.RtAttr)
	// match reports whether the given Nexthop
}{
	unix.NHA_ID: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if nh.ID > 0 {
				b := make([]byte, 4)
				native.PutUint32(b, nh.ID)
				return nl.NewRtAttr(unix.NHA_ID, b)
			}
			return nil
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			if len(attr.Data) < 4 {
				return
			}
			nh.ID = native.Uint32(attr.Data[0:4])
		},
	},
	unix.NHA_BLACKHOLE: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if nh.Blackhole {
				return nl.NewRtAttr(unix.NHA_BLACKHOLE, nil)
			}
			return nil
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			nh.Blackhole = true
		},
	},
	unix.NHA_OIF: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if nh.OIF > 0 {
				b := make([]byte, 4)
				native.PutUint32(b, nh.OIF)
				return nl.NewRtAttr(unix.NHA_OIF, b)
			}
			return nil
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			if len(attr.Data) < 4 {
				return
			}
			nh.OIF = native.Uint32(attr.Data[0:4])
		},
	},
	unix.NHA_GROUP: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if len(nh.Group) == 0 {
				return nil
			}
			b := make([]byte, sizeofNexthopGroupMember*len(nh.Group))
			for i, entry := range nh.Group {
				// Kernel interprets one weight wire = actual weight - 1
				w := entry.Weight
				if w == 0 {
					w = 1
				} else if w > 256 {
					w = 256
				}
				off := i * sizeofNexthopGroupMember
				native.PutUint32(b[off:off+4], entry.ID)
				b[off+4] = uint8(w - 1)
			}
			return nl.NewRtAttr(unix.NHA_GROUP, b)
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			nh.Group = nil
			for off := 0; off+sizeofNexthopGroupMember <= len(attr.Data); off += sizeofNexthopGroupMember {
				nh.Group = append(nh.Group, NexthopGroupMember{
					ID:     native.Uint32(attr.Data[off : off+4]),
					Weight: uint16(attr.Data[off+4]) + 1,
				})
			}
		},
	},
	unix.NHA_GROUP_TYPE: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if nh.GroupType != NEXTHOP_GRP_TYPE_MPATH {
				b := make([]byte, 2)
				native.PutUint16(b, nh.GroupType)
				return nl.NewRtAttr(unix.NHA_GROUP_TYPE, b)
			}
			return nil
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			if len(attr.Data) < 2 {
				return
			}
			nh.GroupType = native.Uint16(attr.Data[0:2])
		},
	},
	nl.NHA_RES_GROUP: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if nh.ResilientGroup == nil {
				return nil
			}
			// Strict netlink validation requires the NLA_F_NESTED
			// flag on nested attributes.
			attr := nl.NewRtAttr(nl.NHA_RES_GROUP|int(nl.NLA_F_NESTED), nil)
			if nh.ResilientGroup.Buckets > 0 {
				b := make([]byte, 2)
				native.PutUint16(b, nh.ResilientGroup.Buckets)
				attr.AddRtAttr(nl.NHA_RES_GROUP_BUCKETS, b)
			}
			if nh.ResilientGroup.IdleTimer > 0 {
				b := make([]byte, 4)
				native.PutUint32(b, nh.ResilientGroup.IdleTimer*nexthopResilientGroupUserHz)
				attr.AddRtAttr(nl.NHA_RES_GROUP_IDLE_TIMER, b)
			}
			if nh.ResilientGroup.UnbalancedTimer > 0 {
				b := make([]byte, 4)
				native.PutUint32(b, nh.ResilientGroup.UnbalancedTimer*nexthopResilientGroupUserHz)
				attr.AddRtAttr(nl.NHA_RES_GROUP_UNBALANCED_TIMER, b)
			}
			return attr
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			nested, err := nl.ParseRouteAttr(attr.Data)
			if err != nil {
				return
			}
			res := &NexthopResilientGroup{}
			for _, a := range nested {
				switch a.Attr.Type & nl.NLA_TYPE_MASK {
				case nl.NHA_RES_GROUP_BUCKETS:
					if len(a.Value) >= 2 {
						res.Buckets = native.Uint16(a.Value[0:2])
					}
				case nl.NHA_RES_GROUP_IDLE_TIMER:
					if len(a.Value) >= 4 {
						res.IdleTimer = native.Uint32(a.Value[0:4]) / nexthopResilientGroupUserHz
					}
				case nl.NHA_RES_GROUP_UNBALANCED_TIMER:
					if len(a.Value) >= 4 {
						res.UnbalancedTimer = native.Uint32(a.Value[0:4]) / nexthopResilientGroupUserHz
					}
				case nl.NHA_RES_GROUP_UNBALANCED_TIME:
					if len(a.Value) >= 8 {
						res.UnbalancedTime = native.Uint64(a.Value[0:8]) / nexthopResilientGroupUserHz
					}
				}
			}
			nh.ResilientGroup = res
		},
	},
	unix.NHA_GATEWAY: {
		encode: func(nh *Nexthop) *nl.RtAttr {
			if nh.Gateway != nil {
				if gw4 := nh.Gateway.To4(); gw4 != nil {
					return nl.NewRtAttr(unix.NHA_GATEWAY, gw4)
				}
				return nl.NewRtAttr(unix.NHA_GATEWAY, nh.Gateway)
			}
			return nil
		},
		decode: func(nh *Nexthop, attr *nl.RtAttr) {
			if len(attr.Data) != 0 {
				nh.Gateway = make(net.IP, len(attr.Data))
				copy(nh.Gateway, attr.Data)
			}
		},
	},
}

// encodeNexthopAttrs encodes the attributes in the Nexthop into the slice of
// RtAttr. The targetAttrs specifies which attributes to encode. This is needed
// because for each operations, there are different supported attributes.
func encodeNexthopAttrs(nh *Nexthop, targetAttrs []uint16) []*nl.RtAttr {
	var rtAttrs []*nl.RtAttr

	for _, attrType := range targetAttrs {
		handler, found := nexthopAttrHandlers[attrType]
		if !found || handler.encode == nil {
			continue
		}
		attr := handler.encode(nh)
		if attr != nil {
			rtAttrs = append(rtAttrs, attr)
		}
	}

	return rtAttrs
}

// decodeNexthopAttrs decodes the attributes in the slice of RtAttr into the
// Nexthop.
func decodeNexthopAttrs(nh *Nexthop, attrs []*nl.RtAttr) {
	for _, attr := range attrs {
		handler, found := nexthopAttrHandlers[attr.Type]
		if !found || handler.decode == nil {
			continue
		}
		handler.decode(nh, attr)
	}
}

func parseNhmsg(m []byte) (*Nexthop, error) {
	msg := nl.DeserializeNhmsg(m)

	rawAttrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}

	rtAttrs := make([]*nl.RtAttr, 0, len(rawAttrs))
	for _, rawAttr := range rawAttrs {
		rtAttrs = append(rtAttrs, nl.NewRtAttr(int(rawAttr.Attr.Type&nl.NLA_TYPE_MASK), rawAttr.Value))
	}

	nh := &Nexthop{
		Protocol: RouteProtocol(msg.Protocol),
	}

	decodeNexthopAttrs(nh, rtAttrs)

	return nh, nil
}

func deriveFamilyFromNexthop(nh *Nexthop) uint8 {
	if len(nh.Group) > 0 {
		return uint8(FAMILY_ALL)
	}
	if nh.Gateway == nil || nh.Gateway.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

func prepareNewNexthop(nh *Nexthop, req *nl.NetlinkRequest, msg *nl.Nhmsg) error {
	if nh.ResilientGroup != nil && nh.GroupType != NEXTHOP_GRP_TYPE_RES {
		return fmt.Errorf("nexthop: ResilientGroup requires GroupType to be NEXTHOP_GRP_TYPE_RES")
	}
	if nh.GroupType != NEXTHOP_GRP_TYPE_MPATH && len(nh.Group) == 0 {
		return fmt.Errorf("nexthop: GroupType is set but Group is empty")
	}

	var rtAttrs []*nl.RtAttr

	// We can find the supported attributes from the kernel source code:
	// https://github.com/torvalds/linux/blob/e53642b87a4f4b03a8d7e5f8507fc3cd0c595ea6/net/ipv4/nexthop.c#L32
	//
	// We need a special handling for NHA_ID here as for the NEWNEXTHOP
	// operation, the zero ID is allowed for ID auto allocation.
	b := make([]byte, 4)
	native.PutUint32(b, nh.ID)
	rtAttrs = append(rtAttrs, nl.NewRtAttr(unix.NHA_ID, b))

	rtAttrs = append(rtAttrs, encodeNexthopAttrs(nh, []uint16{
		unix.NHA_BLACKHOLE,
		unix.NHA_OIF,
		unix.NHA_GATEWAY,
		unix.NHA_GROUP,
		unix.NHA_GROUP_TYPE,
		nl.NHA_RES_GROUP,
	})...)

	msg.Family = deriveFamilyFromNexthop(nh)
	msg.Protocol = uint8(nh.Protocol)

	req.AddData(msg)
	for _, attr := range rtAttrs {
		req.AddData(attr)
	}

	return nil
}

func prepareDelNexthop(nh *Nexthop, req *nl.NetlinkRequest, msg *nl.Nhmsg) error {
	// We can find the supported attributes from the kernel source code:
	// https://github.com/torvalds/linux/blob/e53642b87a4f4b03a8d7e5f8507fc3cd0c595ea6/net/ipv4/nexthop.c#L52
	rtAttrs := encodeNexthopAttrs(nh, []uint16{
		unix.NHA_ID,
	})

	msg.Family = deriveFamilyFromNexthop(nh)

	req.AddData(msg)
	for _, attr := range rtAttrs {
		req.AddData(attr)
	}

	return nil
}
