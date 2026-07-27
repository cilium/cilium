package netlink

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NexthopAdd will add a nexthop to the system.
// Equivalent to: `ip nexthop add $nexthop`
func NexthopAdd(nh *Nexthop) error {
	return pkgHandle.NexthopAdd(nh)
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
	return pkgHandle.NexthopReplace(nh)
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
	return pkgHandle.NexthopDel(nh)
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
	return pkgHandle.NexthopList()
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
		rtAttrs = append(rtAttrs, nl.NewRtAttr(int(rawAttr.Attr.Type), rawAttr.Value))
	}

	nh := &Nexthop{
		Protocol: RouteProtocol(msg.Protocol),
	}

	decodeNexthopAttrs(nh, rtAttrs)

	return nh, nil
}

func deriveFamilyFromNexthop(nh *Nexthop) uint8 {
	if nh.Gateway == nil || nh.Gateway.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

func prepareNewNexthop(nh *Nexthop, req *nl.NetlinkRequest, msg *nl.Nhmsg) error {
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
