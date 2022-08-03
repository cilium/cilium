package monitor

import "github.com/cilium/cilium/pkg/types"

// Socket trace event point with respect to service translation
const (
	XlatePointUnknown = iota
	XlatePointPreDirectionFwd
	XlatePointPostDirectionFwd
	XlatePointPreDirectionRev
	XlatePointPostDirectionRev
)

// L4 protocol for socket trace event
const (
	L4ProtocolUnknown = iota
	L4ProtocolTCP
	L4ProtocolUDP
)

// TraceSockNotify is message format for socket trace notifications sent from datapath.
// Keep this in sync to the datapath structure (trace_sock_notify) defined in
// bpf/lib/trace_sock.h
type TraceSockNotify struct {
	Type       uint8
	XlatePoint uint8
	DstIP      types.IPv6
	DstPort    uint16
	SockCookie uint64
	CgroupId   uint64
	L4Proto    uint8
	Flags      uint8
}
