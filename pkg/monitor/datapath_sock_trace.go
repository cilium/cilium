// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/types"
)

// Service translation event point in socket trace event messages
const (
	XlatePointUnknown = iota
	XlatePointPreDirectionFwd
	XlatePointPostDirectionFwd
	XlatePointPreDirectionRev
	XlatePointPostDirectionRev
)

// L4 protocol for socket trace event messages
const (
	L4ProtocolUnknown = iota
	L4ProtocolTCP
	L4ProtocolUDP
)

const TraceSockNotifyFlagIPv6 uint8 = 0x1

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

func (t *TraceSockNotify) DumpDebug(prefix string) {
	buf := bufio.NewWriter(os.Stdout)

	fmt.Fprintf(buf, "%s [%s] cgroup_id: %d sock_cookie: %d, dst [%s]:%d %s \n",
		prefix, t.XlatePointStr(), t.CgroupId, t.SockCookie, t.IP(), t.DstPort, t.L4ProtoStr())
	buf.Flush()
}

func (t *TraceSockNotify) XlatePointStr() string {
	switch t.XlatePoint {
	case XlatePointPreDirectionFwd:
		return "pre-xlate-fwd"
	case XlatePointPostDirectionFwd:
		return "post-xlate-fwd"
	case XlatePointPreDirectionRev:
		return "pre-xlate-rev"
	case XlatePointPostDirectionRev:
		return "post-xlate-rev"
	default:
		return "unknown"
	}
}

// IP returns the IPv4 or IPv6 address field.
func (t *TraceSockNotify) IP() net.IP {
	if (t.Flags & TraceSockNotifyFlagIPv6) != 0 {
		return t.DstIP[:]
	}
	return t.DstIP[:4]
}

func (t *TraceSockNotify) L4ProtoStr() string {
	switch t.L4Proto {
	case L4ProtocolTCP:
		return "tcp"
	case L4ProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}
