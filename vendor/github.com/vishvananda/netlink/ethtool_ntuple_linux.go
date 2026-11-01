package netlink

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ethtool RX flow classification (n-tuple) commands. These manage RX flow
// steering rules via the SIOCETHTOOL ioctl; the kernel does not expose them
// over ethtool netlink. See include/uapi/linux/ethtool.h.
const (
	ETHTOOL_GRXCLSRLCNT = 0x0000002e // get RX class rule count
	ETHTOOL_GRXCLSRULE  = 0x0000002f // get one RX classification rule
	ETHTOOL_GRXCLSRLALL = 0x00000030 // get all RX classification rule locations
	ETHTOOL_SRXCLSRLDEL = 0x00000031 // delete RX classification rule
	ETHTOOL_SRXCLSRLINS = 0x00000032 // insert RX classification rule
)

// Flow types for ethtoolRxFlowSpec.flowType (subset; enum in ethtool.h).
const (
	TCP_V4_FLOW = 0x01
	UDP_V4_FLOW = 0x02
	TCP_V6_FLOW = 0x05
	UDP_V6_FLOW = 0x06
	ETHER_FLOW  = 0x12
)

// Special rule insertion locations from include/uapi/linux/ethtool.h.
// RX_CLS_LOC_SPECIAL marks special locations and is reported by drivers that
// support them.
const (
	RX_CLS_LOC_SPECIAL uint32 = 0x80000000
	RX_CLS_LOC_ANY     uint32 = 0xffffffff
	RX_CLS_LOC_FIRST   uint32 = 0xfffffffe
	RX_CLS_LOC_LAST    uint32 = 0xfffffffd
)

// ETHTOOL_RX_FLOW_SPEC_RING masks the queue index out of ring_cookie (the low
// 32 bits); bits 32-39 hold an optional VF id which we leave zero.
const ethtoolRxFlowSpecRing = 0x00000000FFFFFFFF

// Special ring_cookie actions from include/uapi/linux/ethtool.h.
const (
	ethtoolRxClsFlowDisc = 0xffffffffffffffff // RX_CLS_FLOW_DISC (discard)
	ethtoolRxClsFlowWake = 0xfffffffffffffffe // RX_CLS_FLOW_WAKE (Wake-on-LAN)
)

// Flags ORed into ethtoolRxFlowSpec.flowType (FLOW_EXT, FLOW_MAC_EXT and
// FLOW_RSS in include/uapi/linux/ethtool.h).
const (
	ethtoolFlowExt    = 0x80000000
	ethtoolFlowMACExt = 0x40000000
	ethtoolFlowRSS    = 0x20000000
)

// NetDevRxFlow is a typed RX flow steering rule. Match identifies the flow to
// match and supplies both the value (h_u) and mask (m_u) halves of the rule.
// Action describes what happens to matching packets.
type NetDevRxFlow struct {
	// Match is the flow matcher; its concrete type selects the flow type.
	Match NetDevRxFlowMatch
	// Action is applied to matching packets.
	Action NetDevRxFlowAction
	// Location is the rule slot. Use RX_CLS_LOC_ANY to let the kernel pick;
	// on insert the chosen location is returned.
	Location uint32
}

// NetDevRxFlowMatch is implemented by the typed flow matchers. It produces the
// ethtool flow_type and the 52-byte value/mask union blobs.
type NetDevRxFlowMatch interface {
	flowType() uint32
	// serialize returns the value (h_u) and mask (m_u) 52-byte union contents.
	serialize() (val [52]byte, mask [52]byte)
}

// EtherFlow matches on Ethernet header fields (ETHER_FLOW). A zero field in a
// mask means "don't care"; an all-ones mask means "must match exactly". This is
// the matcher used by the KubeVirt AF_XDP example (steer by destination MAC).
type EtherFlow struct {
	SrcMAC, SrcMACMask  net.HardwareAddr
	DstMAC, DstMACMask  net.HardwareAddr
	EthProto, ProtoMask uint16 // EtherType, host byte order
}

func (EtherFlow) flowType() uint32 { return ETHER_FLOW }

func (f EtherFlow) serialize() (val [52]byte, mask [52]byte) {
	// struct ethhdr { u8 h_dest[6]; u8 h_source[6]; __be16 h_proto; }
	putMAC(val[0:6], f.DstMAC)
	putMAC(val[6:12], f.SrcMAC)
	// ethhdr.h_proto is __be16 (network order).
	networkOrder.PutUint16(val[12:14], f.EthProto)
	putMAC(mask[0:6], f.DstMACMask)
	putMAC(mask[6:12], f.SrcMACMask)
	networkOrder.PutUint16(mask[12:14], f.ProtoMask)
	return val, mask
}

// TCP4Flow and UDP4Flow match on IPv4 TCP/UDP 5-tuple fields. Addresses and
// ports are given in host byte order and serialized in network byte order as the kernel
// (struct ethtool_tcpip4_spec) expects. A zero mask field means "don't care".
type TCP4Flow struct{ TCPIP4Fields }
type UDP4Flow struct{ TCPIP4Fields }

// TCPIP4Fields holds the IPv4 TCP/UDP match fields shared by TCP4Flow/UDP4Flow.
type TCPIP4Fields struct {
	SrcIP, SrcIPMask     net.IP // IPv4
	DstIP, DstIPMask     net.IP
	SrcPort, SrcPortMask uint16
	DstPort, DstPortMask uint16
}

func (TCP4Flow) flowType() uint32 { return TCP_V4_FLOW }
func (UDP4Flow) flowType() uint32 { return UDP_V4_FLOW }

func (f TCP4Flow) serialize() ([52]byte, [52]byte) { return f.TCPIP4Fields.serialize() }
func (f UDP4Flow) serialize() ([52]byte, [52]byte) { return f.TCPIP4Fields.serialize() }

func (f TCPIP4Fields) serialize() (val [52]byte, mask [52]byte) {
	// struct ethtool_tcpip4_spec { __be32 ip4src; __be32 ip4dst;
	//                              __be16 psrc; __be16 pdst; __u8 tos; }
	putIP4(val[0:4], f.SrcIP)
	putIP4(val[4:8], f.DstIP)
	networkOrder.PutUint16(val[8:10], f.SrcPort)
	networkOrder.PutUint16(val[10:12], f.DstPort)
	putIP4(mask[0:4], f.SrcIPMask)
	putIP4(mask[4:8], f.DstIPMask)
	networkOrder.PutUint16(mask[8:10], f.SrcPortMask)
	networkOrder.PutUint16(mask[10:12], f.DstPortMask)
	return val, mask
}

// TCP6Flow and UDP6Flow match on IPv6 TCP/UDP 5-tuple fields. Addresses are
// serialized as 16 network-order bytes, and ports are serialized in network
// byte order as struct ethtool_tcpip6_spec expects. A zero mask field means
// "don't care". Address masks are passed to the kernel unchanged, so callers
// can use IPv6 CIDR masks; individual drivers may restrict which masks their
// hardware can offload.
type TCP6Flow struct{ TCPIP6Fields }
type UDP6Flow struct{ TCPIP6Fields }

// TCPIP6Fields holds the IPv6 TCP/UDP match fields shared by TCP6Flow/UDP6Flow.
type TCPIP6Fields struct {
	SrcIP, SrcIPMask     net.IP // IPv6
	DstIP, DstIPMask     net.IP
	SrcPort, SrcPortMask uint16
	DstPort, DstPortMask uint16
}

func (TCP6Flow) flowType() uint32 { return TCP_V6_FLOW }
func (UDP6Flow) flowType() uint32 { return UDP_V6_FLOW }

func (f TCP6Flow) serialize() ([52]byte, [52]byte) { return f.TCPIP6Fields.serialize() }
func (f UDP6Flow) serialize() ([52]byte, [52]byte) { return f.TCPIP6Fields.serialize() }

func (f TCPIP6Fields) serialize() (val [52]byte, mask [52]byte) {
	// struct ethtool_tcpip6_spec { __be32 ip6src[4]; __be32 ip6dst[4];
	//                              __be16 psrc; __be16 pdst; __u8 tclass; }
	putIP6(val[0:16], f.SrcIP)
	putIP6(val[16:32], f.DstIP)
	networkOrder.PutUint16(val[32:34], f.SrcPort)
	networkOrder.PutUint16(val[34:36], f.DstPort)
	putIP6(mask[0:16], f.SrcIPMask)
	putIP6(mask[16:32], f.DstIPMask)
	networkOrder.PutUint16(mask[32:34], f.SrcPortMask)
	networkOrder.PutUint16(mask[34:36], f.DstPortMask)
	return val, mask
}

// ethtoolRxFlowSpec is the logical representation of struct
// ethtool_rx_flow_spec. It is encoded explicitly because the Linux 386 ABI
// aligns uint64 fields to 4 bytes while the other supported Linux ABIs align
// them to 8 bytes.
type ethtoolRxFlowSpec struct {
	flowType   uint32
	hU         [52]byte
	hExt       [20]byte
	mU         [52]byte
	mExt       [20]byte
	ringCookie uint64
	location   uint32
}

// ethtoolRxnfc is the logical representation of struct ethtool_rxnfc. Its Go
// layout is not passed to the kernel; serializeEthtoolRxnfc produces the native
// UAPI byte layout instead.
type ethtoolRxnfc struct {
	cmd             uint32
	flowType        uint32
	data            uint64
	fs              ethtoolRxFlowSpec
	ruleCntOrRssCtx uint32
}

type ethtoolRxnfcLayout struct {
	size                  int
	ringCookieOffset      int
	locationOffset        int
	ruleCntOrRssCtxOffset int
	ruleLocsOffset        int
}

const (
	ethtoolRxnfcCmdOffset      = 0
	ethtoolRxnfcFlowTypeOffset = 4
	ethtoolRxnfcDataOffset     = 8
	ethtoolRxnfcFlowSpecOffset = 16

	ethtoolRxFlowSpecFlowTypeOffset = 0
	ethtoolRxFlowSpecHUOffset       = 4
	ethtoolRxFlowSpecHExtOffset     = 56
	ethtoolRxFlowSpecMUOffset       = 76
	ethtoolRxFlowSpecMExtOffset     = 128
)

var (
	// Linux UAPI layout used by all Go-supported Linux architectures except 386.
	ethtoolRxnfcLayoutAligned8 = ethtoolRxnfcLayout{
		size:                  192,
		ringCookieOffset:      152,
		locationOffset:        160,
		ruleCntOrRssCtxOffset: 184,
		ruleLocsOffset:        188,
	}
	// The i386 ABI gives uint64 fields only 4-byte alignment.
	ethtoolRxnfcLayoutAligned4 = ethtoolRxnfcLayout{
		size:                  180,
		ringCookieOffset:      148,
		locationOffset:        156,
		ruleCntOrRssCtxOffset: 176,
		ruleLocsOffset:        180,
	}
)

func nativeEthtoolRxnfcLayout() ethtoolRxnfcLayout {
	if runtime.GOARCH == "386" {
		return ethtoolRxnfcLayoutAligned4
	}
	return ethtoolRxnfcLayoutAligned8
}

func serializeEthtoolRxnfc(nfc *ethtoolRxnfc, layout ethtoolRxnfcLayout) ([]byte, error) {
	var ruleCapacity uint32
	// GRXCLSRLALL needs space for the fixed-size struct plus an array of rule
	// locations, sized by rule_cnt. Other commands need only the struct.
	if nfc.cmd == ETHTOOL_GRXCLSRLALL {
		ruleCapacity = nfc.ruleCntOrRssCtx
	}
	bufLen := uint64(layout.size)
	if ruleCapacity != 0 {
		locsLen := uint64(layout.ruleLocsOffset) + uint64(ruleCapacity)*4
		if locsLen > bufLen {
			bufLen = locsLen
		}
	}
	if bufLen > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("netlink: RX flow rule count %d is too large", ruleCapacity)
	}

	buf := make([]byte, int(bufLen))
	native.PutUint32(buf[ethtoolRxnfcCmdOffset:], nfc.cmd)
	native.PutUint32(buf[ethtoolRxnfcFlowTypeOffset:], nfc.flowType)
	native.PutUint64(buf[ethtoolRxnfcDataOffset:], nfc.data)

	fs := buf[ethtoolRxnfcFlowSpecOffset:]
	native.PutUint32(fs[ethtoolRxFlowSpecFlowTypeOffset:], nfc.fs.flowType)
	copy(fs[ethtoolRxFlowSpecHUOffset:], nfc.fs.hU[:])
	copy(fs[ethtoolRxFlowSpecHExtOffset:], nfc.fs.hExt[:])
	copy(fs[ethtoolRxFlowSpecMUOffset:], nfc.fs.mU[:])
	copy(fs[ethtoolRxFlowSpecMExtOffset:], nfc.fs.mExt[:])
	native.PutUint64(fs[layout.ringCookieOffset:], nfc.fs.ringCookie)
	native.PutUint32(fs[layout.locationOffset:], nfc.fs.location)
	native.PutUint32(buf[layout.ruleCntOrRssCtxOffset:], nfc.ruleCntOrRssCtx)
	return buf, nil
}

func deserializeEthtoolRxnfc(nfc *ethtoolRxnfc, buf []byte, layout ethtoolRxnfcLayout) error {
	if len(buf) < layout.size {
		return fmt.Errorf("netlink: short RX flow classification response")
	}

	nfc.cmd = native.Uint32(buf[ethtoolRxnfcCmdOffset:])
	nfc.flowType = native.Uint32(buf[ethtoolRxnfcFlowTypeOffset:])
	nfc.data = native.Uint64(buf[ethtoolRxnfcDataOffset:])

	fs := buf[ethtoolRxnfcFlowSpecOffset:]
	nfc.fs.flowType = native.Uint32(fs[ethtoolRxFlowSpecFlowTypeOffset:])
	copy(nfc.fs.hU[:], fs[ethtoolRxFlowSpecHUOffset:ethtoolRxFlowSpecHExtOffset])
	copy(nfc.fs.hExt[:], fs[ethtoolRxFlowSpecHExtOffset:ethtoolRxFlowSpecMUOffset])
	copy(nfc.fs.mU[:], fs[ethtoolRxFlowSpecMUOffset:ethtoolRxFlowSpecMExtOffset])
	copy(nfc.fs.mExt[:], fs[ethtoolRxFlowSpecMExtOffset:ethtoolRxFlowSpecMExtOffset+len(nfc.fs.mExt)])
	nfc.fs.ringCookie = native.Uint64(fs[layout.ringCookieOffset:])
	nfc.fs.location = native.Uint32(fs[layout.locationOffset:])
	nfc.ruleCntOrRssCtx = native.Uint32(buf[layout.ruleCntOrRssCtxOffset:])
	return nil
}

func putMAC(dst []byte, mac net.HardwareAddr) {
	if len(mac) >= 6 {
		copy(dst, mac[:6])
	}
}

func putIP4(dst []byte, ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		copy(dst, ip4)
	}
}

func putIP6(dst []byte, ip net.IP) {
	if ip.To4() != nil {
		return
	}
	if ip6 := ip.To16(); ip6 != nil {
		copy(dst, ip6)
	}
}

func validateHardwareAddr(field string, addr net.HardwareAddr) error {
	if len(addr) != 0 && len(addr) != 6 {
		return fmt.Errorf("netlink: %s must contain exactly 6 bytes", field)
	}
	return nil
}

func validateIPv4(field string, ip net.IP) error {
	if len(ip) != 0 && ip.To4() == nil {
		return fmt.Errorf("netlink: %s must be an IPv4 address", field)
	}
	return nil
}

func validateIPv6(field string, ip net.IP) error {
	if ip.To4() != nil {
		return fmt.Errorf("netlink: %s does not support IPv4 or IPv4-mapped IPv6 addresses", field)
	}
	if len(ip) != 0 && ip.To16() == nil {
		return fmt.Errorf("netlink: %s must be an IPv6 address", field)
	}
	return nil
}

func validateNetDevRxFlowMatch(match NetDevRxFlowMatch) error {
	switch m := match.(type) {
	case EtherFlow:
		return validateEtherFlow(m)
	case *EtherFlow:
		if m == nil {
			return fmt.Errorf("netlink: NetDevRxFlow.Match must be set")
		}
		return validateEtherFlow(*m)
	case TCP4Flow:
		return validateTCPIP4Fields("TCP4Flow", m.TCPIP4Fields)
	case *TCP4Flow:
		if m == nil {
			return fmt.Errorf("netlink: NetDevRxFlow.Match must be set")
		}
		return validateTCPIP4Fields("TCP4Flow", m.TCPIP4Fields)
	case UDP4Flow:
		return validateTCPIP4Fields("UDP4Flow", m.TCPIP4Fields)
	case *UDP4Flow:
		if m == nil {
			return fmt.Errorf("netlink: NetDevRxFlow.Match must be set")
		}
		return validateTCPIP4Fields("UDP4Flow", m.TCPIP4Fields)
	case TCP6Flow:
		return validateTCPIP6Fields("TCP6Flow", m.TCPIP6Fields)
	case *TCP6Flow:
		if m == nil {
			return fmt.Errorf("netlink: NetDevRxFlow.Match must be set")
		}
		return validateTCPIP6Fields("TCP6Flow", m.TCPIP6Fields)
	case UDP6Flow:
		return validateTCPIP6Fields("UDP6Flow", m.TCPIP6Fields)
	case *UDP6Flow:
		if m == nil {
			return fmt.Errorf("netlink: NetDevRxFlow.Match must be set")
		}
		return validateTCPIP6Fields("UDP6Flow", m.TCPIP6Fields)
	default:
		return fmt.Errorf("netlink: unsupported NetDevRxFlow.Match type %T", match)
	}
}

func validateEtherFlow(flow EtherFlow) error {
	fields := []struct {
		name string
		addr net.HardwareAddr
	}{
		{"EtherFlow.SrcMAC", flow.SrcMAC},
		{"EtherFlow.SrcMACMask", flow.SrcMACMask},
		{"EtherFlow.DstMAC", flow.DstMAC},
		{"EtherFlow.DstMACMask", flow.DstMACMask},
	}
	for _, field := range fields {
		if err := validateHardwareAddr(field.name, field.addr); err != nil {
			return err
		}
	}
	return nil
}

func validateTCPIP4Fields(flowType string, fields TCPIP4Fields) error {
	addresses := []struct {
		name string
		ip   net.IP
	}{
		{flowType + ".SrcIP", fields.SrcIP},
		{flowType + ".SrcIPMask", fields.SrcIPMask},
		{flowType + ".DstIP", fields.DstIP},
		{flowType + ".DstIPMask", fields.DstIPMask},
	}
	for _, address := range addresses {
		if err := validateIPv4(address.name, address.ip); err != nil {
			return err
		}
	}
	return nil
}

func validateTCPIP6Fields(flowType string, fields TCPIP6Fields) error {
	addresses := []struct {
		name string
		ip   net.IP
	}{
		{flowType + ".SrcIP", fields.SrcIP},
		{flowType + ".SrcIPMask", fields.SrcIPMask},
		{flowType + ".DstIP", fields.DstIP},
		{flowType + ".DstIPMask", fields.DstIPMask},
	}
	for _, address := range addresses {
		if err := validateIPv6(address.name, address.ip); err != nil {
			return err
		}
	}
	return nil
}

// NetDevRxFlowInsert inserts (or updates) an RX flow steering rule on dev,
// directing matching packets to flow.Action.Queue. Other actions are not yet
// supported. It returns the rule location the kernel assigned. Requires CAP_NET_ADMIN.
// Equivalent to: ethtool --config-ntuple <dev> flow-type ... action <queue>
func NetDevRxFlowInsert(dev string, flow NetDevRxFlow) (uint32, error) {
	if flow.Match == nil {
		return 0, fmt.Errorf("netlink: NetDevRxFlow.Match must be set")
	}
	if err := validateNetDevRxFlowMatch(flow.Match); err != nil {
		return 0, err
	}
	queueOnly := NetDevRxFlowAction{Queue: flow.Action.Queue}
	if flow.Action != queueOnly {
		return 0, fmt.Errorf("netlink: RX flow insertion only supports direct queue actions: %w", ErrNotImplemented)
	}
	val, mask := flow.Match.serialize()
	nfc := ethtoolRxnfc{
		cmd: ETHTOOL_SRXCLSRLINS,
		fs: ethtoolRxFlowSpec{
			flowType:   flow.Match.flowType(),
			hU:         val,
			mU:         mask,
			ringCookie: uint64(flow.Action.Queue) & ethtoolRxFlowSpecRing,
			location:   flow.Location,
		},
	}
	if err := ethtoolRxnfcIoctl(dev, &nfc); err != nil {
		return 0, err
	}
	// On insert with RX_CLS_LOC_ANY the kernel writes back the chosen location.
	return nfc.fs.location, nil
}

// NetDevRxFlowDelete removes the RX flow steering rule at the given location.
func NetDevRxFlowDelete(dev string, location uint32) error {
	nfc := ethtoolRxnfc{
		cmd: ETHTOOL_SRXCLSRLDEL,
		fs:  ethtoolRxFlowSpec{location: location},
	}
	return ethtoolRxnfcIoctl(dev, &nfc)
}

// NetDevRxFlowList returns the locations of all RX flow steering rules on dev.
func NetDevRxFlowList(dev string) ([]uint32, error) {
	// First get the rule count.
	cnt := ethtoolRxnfc{cmd: ETHTOOL_GRXCLSRLCNT}
	if err := ethtoolRxnfcIoctl(dev, &cnt); err != nil {
		return nil, err
	}
	n := cnt.ruleCntOrRssCtx
	if n == 0 {
		return nil, nil
	}
	layout := nativeEthtoolRxnfcLayout()
	nfc := ethtoolRxnfc{
		cmd:             ETHTOOL_GRXCLSRLALL,
		ruleCntOrRssCtx: n,
	}
	buf, err := serializeEthtoolRxnfc(&nfc, layout)
	if err != nil {
		return nil, err
	}
	if err := ethtoolIoctl(dev, unsafe.Pointer(&buf[0])); err != nil {
		return nil, err
	}
	return parseNetDevRxFlowLocations(buf, layout, n)
}

func parseNetDevRxFlowLocations(buf []byte, layout ethtoolRxnfcLayout, capacity uint32) ([]uint32, error) {
	if len(buf) < layout.size {
		return nil, fmt.Errorf("netlink: short RX flow rule response")
	}
	n := native.Uint32(buf[layout.ruleCntOrRssCtxOffset:])
	if n > capacity {
		return nil, fmt.Errorf("netlink: kernel returned %d RX flow rules, buffer holds %d", n, capacity)
	}
	locsOff := layout.ruleLocsOffset
	if uint64(n) > uint64((len(buf)-locsOff)/4) {
		return nil, fmt.Errorf("netlink: short RX flow rule location response")
	}
	locs := make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		off := locsOff + int(i)*4
		locs[i] = native.Uint32(buf[off : off+4])
	}
	return locs, nil
}

// NetDevRxFlowTable describes the RX flow steering rule table of a device.
type NetDevRxFlowTable struct {
	// Rules is the number of rules currently installed.
	Rules uint32
	// Size is the number of rule locations, or zero if unavailable.
	Size uint32
	// SpecialLocations reports whether the driver selects a location for
	// RX_CLS_LOC_ANY. Such drivers may reject explicit locations or other
	// special values. Otherwise callers must choose a location themselves.
	SpecialLocations bool
}

// NetDevRxFlowTableGet returns the RX flow steering rule table of dev.
func NetDevRxFlowTableGet(dev string) (*NetDevRxFlowTable, error) {
	return netDevRxFlowTableGet(func(nfc *ethtoolRxnfc) error {
		return ethtoolRxnfcIoctl(dev, nfc)
	})
}

func netDevRxFlowTableGet(ioctl func(*ethtoolRxnfc) error) (*NetDevRxFlowTable, error) {
	nfc := ethtoolRxnfc{cmd: ETHTOOL_GRXCLSRLCNT}
	if err := ioctl(&nfc); err != nil {
		return nil, err
	}
	table := parseNetDevRxFlowTable(&nfc)
	if table.Size != 0 {
		return table, nil
	}
	// Some drivers report the size only with GRXCLSRLALL, even for an empty table.
	nfc = ethtoolRxnfc{cmd: ETHTOOL_GRXCLSRLALL, ruleCntOrRssCtx: table.Rules}
	if err := ioctl(&nfc); err != nil {
		return nil, err
	}
	result := parseNetDevRxFlowTable(&nfc)
	result.SpecialLocations = table.SpecialLocations
	return result, nil
}

func parseNetDevRxFlowTable(nfc *ethtoolRxnfc) *NetDevRxFlowTable {
	// The low 32 bits of data hold the table size and the special location flag.
	data := uint32(nfc.data)
	return &NetDevRxFlowTable{
		Rules:            nfc.ruleCntOrRssCtx,
		Size:             data &^ RX_CLS_LOC_SPECIAL,
		SpecialLocations: data&RX_CLS_LOC_SPECIAL != 0,
	}
}

// NetDevRxFlowAction describes what an RX flow steering rule does with the
// packets it matches, decoded from the ethtool_rxnfc UAPI in
// include/uapi/linux/ethtool.h. See ethtool_rx_flow_rule_create() in
// net/ethtool/ioctl.c for the kernel's corresponding action decoder.
type NetDevRxFlowAction struct {
	// Drop is set for rules that discard matching packets.
	Drop bool
	// WakeOnLAN is set for rules that use matching packets to wake the system.
	WakeOnLAN bool
	// VF is zero for rules that deliver to the device itself, or one more than
	// the index of the virtual function that receives matching packets.
	VF uint8
	// Queue is the receive queue for matching packets, within the VF if VF is
	// nonzero. If UsesRSSContext is set, Queue is added to the queue that
	// RSSContext selects instead.
	Queue uint32
	// UsesRSSContext is set for rules that spread matching packets over the
	// queues of RSSContext.
	UsesRSSContext bool
	RSSContext     uint32
}

// NetDevRxFlowActionGet returns the action of the RX flow steering rule at the
// given location on dev, even if NetDevRxFlowGet does not support the rule's
// match criteria. If the action uses an unsupported encoding, the returned
// error wraps ErrNotImplemented.
func NetDevRxFlowActionGet(dev string, location uint32) (*NetDevRxFlowAction, error) {
	nfc := ethtoolRxnfc{
		cmd: ETHTOOL_GRXCLSRULE,
		fs:  ethtoolRxFlowSpec{location: location},
	}
	if err := ethtoolRxnfcIoctl(dev, &nfc); err != nil {
		return nil, err
	}
	return parseNetDevRxFlowAction(&nfc)
}

func parseNetDevRxFlowAction(nfc *ethtoolRxnfc) (*NetDevRxFlowAction, error) {
	switch nfc.fs.ringCookie {
	case ethtoolRxClsFlowDisc:
		return &NetDevRxFlowAction{Drop: true}, nil
	case ethtoolRxClsFlowWake:
		return &NetDevRxFlowAction{WakeOnLAN: true}, nil
	}
	// Queue/VF actions use the low 40 bits. Higher bits may encode unsupported
	// actions, e.g. mlx4's direct QP attachment (EN_ETHTOOL_QP_ATTACH).
	if nfc.fs.ringCookie>>40 != 0 {
		return nil, fmt.Errorf("netlink: RX flow rule %d has unsupported action %#x: %w",
			nfc.fs.location, nfc.fs.ringCookie, ErrNotImplemented)
	}
	action := &NetDevRxFlowAction{
		VF:    uint8(nfc.fs.ringCookie >> 32),
		Queue: uint32(nfc.fs.ringCookie & ethtoolRxFlowSpecRing),
	}
	if nfc.fs.flowType&ethtoolFlowRSS != 0 {
		action.UsesRSSContext = true
		action.RSSContext = nfc.ruleCntOrRssCtx
	}
	return action, nil
}

// NetDevRxFlowGet returns the RX flow steering rule at the given location on
// dev. Only direct queue actions are currently supported. If the rule uses an
// unsupported flow type, match field, extension or action, the returned error
// wraps ErrNotImplemented.
// Equivalent to: ethtool --show-ntuple <dev> rule <location>
func NetDevRxFlowGet(dev string, location uint32) (*NetDevRxFlow, error) {
	nfc := ethtoolRxnfc{
		cmd: ETHTOOL_GRXCLSRULE,
		fs:  ethtoolRxFlowSpec{location: location},
	}
	if err := ethtoolRxnfcIoctl(dev, &nfc); err != nil {
		return nil, err
	}
	return parseNetDevRxFlow(&nfc.fs)
}

func parseNetDevRxFlow(fs *ethtoolRxFlowSpec) (*NetDevRxFlow, error) {
	if fs.flowType&ethtoolFlowRSS != 0 {
		return nil, fmt.Errorf("netlink: RX flow rule %d targets an RSS context: %w",
			fs.location, ErrNotImplemented)
	}
	// Drop, wake-on-LAN and VF actions set bits above the queue index.
	if fs.ringCookie&^ethtoolRxFlowSpecRing != 0 {
		return nil, fmt.Errorf("netlink: RX flow rule %d action %#x is not a queue: %w",
			fs.location, fs.ringCookie, ErrNotImplemented)
	}
	// ethtool_flow_ext stores h_dest at bytes 2:8 and VLAN/data at 8:20.
	// Only masks enabled by their corresponding extension flag are significant.
	if fs.flowType&ethtoolFlowMACExt != 0 && !allZero(fs.mExt[2:8]) ||
		fs.flowType&ethtoolFlowExt != 0 && !allZero(fs.mExt[8:]) {
		return nil, fmt.Errorf("netlink: RX flow rule %d uses flow extensions: %w",
			fs.location, ErrNotImplemented)
	}

	var match NetDevRxFlowMatch
	switch fs.flowType &^ (ethtoolFlowExt | ethtoolFlowMACExt) {
	case ETHER_FLOW:
		match = EtherFlow{
			DstMAC:     macFromBytes(fs.hU[0:6]),
			SrcMAC:     macFromBytes(fs.hU[6:12]),
			EthProto:   networkOrder.Uint16(fs.hU[12:14]),
			DstMACMask: macFromBytes(fs.mU[0:6]),
			SrcMACMask: macFromBytes(fs.mU[6:12]),
			ProtoMask:  networkOrder.Uint16(fs.mU[12:14]),
		}
	case TCP_V4_FLOW:
		match = TCP4Flow{parseTCPIP4Fields(&fs.hU, &fs.mU)}
	case UDP_V4_FLOW:
		match = UDP4Flow{parseTCPIP4Fields(&fs.hU, &fs.mU)}
	case TCP_V6_FLOW:
		match = TCP6Flow{parseTCPIP6Fields(&fs.hU, &fs.mU)}
	case UDP_V6_FLOW:
		match = UDP6Flow{parseTCPIP6Fields(&fs.hU, &fs.mU)}
	default:
		return nil, fmt.Errorf("netlink: RX flow rule %d has unsupported flow type %#x: %w",
			fs.location, fs.flowType, ErrNotImplemented)
	}

	if err := validateNetDevRxFlowMatch(match); err != nil {
		return nil, fmt.Errorf("netlink: RX flow rule %d has unsupported match: %w: %w",
			fs.location, err, ErrNotImplemented)
	}

	// Serializing the decoded mask reproduces the kernel's mask only if no
	// field outside the typed matcher, such as the IPv4 TOS or IPv6 traffic
	// class, takes part in the match.
	if _, mask := match.serialize(); mask != fs.mU {
		return nil, fmt.Errorf("netlink: RX flow rule %d matches fields that %T does not support: %w",
			fs.location, match, ErrNotImplemented)
	}

	return &NetDevRxFlow{
		Match:    match,
		Action:   NetDevRxFlowAction{Queue: uint32(fs.ringCookie)},
		Location: fs.location,
	}, nil
}

func parseTCPIP4Fields(val, mask *[52]byte) TCPIP4Fields {
	return TCPIP4Fields{
		SrcIP:       ipFromBytes(val[0:4]),
		DstIP:       ipFromBytes(val[4:8]),
		SrcPort:     networkOrder.Uint16(val[8:10]),
		DstPort:     networkOrder.Uint16(val[10:12]),
		SrcIPMask:   ipFromBytes(mask[0:4]),
		DstIPMask:   ipFromBytes(mask[4:8]),
		SrcPortMask: networkOrder.Uint16(mask[8:10]),
		DstPortMask: networkOrder.Uint16(mask[10:12]),
	}
}

func parseTCPIP6Fields(val, mask *[52]byte) TCPIP6Fields {
	return TCPIP6Fields{
		SrcIP:       ipFromBytes(val[0:16]),
		DstIP:       ipFromBytes(val[16:32]),
		SrcPort:     networkOrder.Uint16(val[32:34]),
		DstPort:     networkOrder.Uint16(val[34:36]),
		SrcIPMask:   ipFromBytes(mask[0:16]),
		DstIPMask:   ipFromBytes(mask[16:32]),
		SrcPortMask: networkOrder.Uint16(mask[32:34]),
		DstPortMask: networkOrder.Uint16(mask[34:36]),
	}
}

// macFromBytes and ipFromBytes return nil for an all-zero field, which
// serializes the same way, so fields left unset on insert are also unset on
// get.
func macFromBytes(b []byte) net.HardwareAddr {
	if allZero(b) {
		return nil
	}
	return net.HardwareAddr(bytes.Clone(b))
}

func ipFromBytes(b []byte) net.IP {
	if allZero(b) {
		return nil
	}
	return net.IP(bytes.Clone(b))
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ethtoolRxnfcIoctl runs SIOCETHTOOL with an ethtool_rxnfc argument.
func ethtoolRxnfcIoctl(dev string, nfc *ethtoolRxnfc) error {
	layout := nativeEthtoolRxnfcLayout()
	buf, err := serializeEthtoolRxnfc(nfc, layout)
	if err != nil {
		return err
	}
	if err := ethtoolIoctl(dev, unsafe.Pointer(&buf[0])); err != nil {
		return err
	}
	return deserializeEthtoolRxnfc(nfc, buf, layout)
}

// ethtoolIoctl issues SIOCETHTOOL on dev with data pointing at an ethtool
// command struct (whose first u32 is the command).
func ethtoolIoctl(dev string, data unsafe.Pointer) error {
	if err := validateNetDevName(dev); err != nil {
		return err
	}
	fd, err := getSocketUDP()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifreq := &Ifreq{Data: uintptr(data)}
	copy(ifreq.Name[:unix.IFNAMSIZ-1], dev)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(SIOCETHTOOL),
		uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return errno
	}
	return nil
}

func validateNetDevName(dev string) error {
	switch {
	case dev == "":
		return fmt.Errorf("netlink: device name must not be empty")
	case strings.IndexByte(dev, 0) >= 0:
		return fmt.Errorf("netlink: device name %q contains a NUL byte", dev)
	case len(dev) >= unix.IFNAMSIZ:
		return fmt.Errorf("netlink: device name %q exceeds %d bytes", dev, unix.IFNAMSIZ-1)
	default:
		return nil
	}
}
