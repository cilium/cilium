// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/monitor/api"
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

const (
	TraceSockNotifyLen = 40
)

// TraceSockNotify is message format for socket trace notifications sent from datapath.
// Keep this in sync to the datapath structure (trace_sock_notify) defined in
// bpf/lib/trace_sock.h
type TraceSockNotify struct {
	api.DefaultSrcDstGetter

	Type       uint8      `align:"type"`
	XlatePoint uint8      `align:"xlate_point"`
	L4Proto    uint8      `align:"l4_proto"`
	Flags      uint8      `align:"ipv6"`
	DstPort    uint16     `align:"dst_port"`
	_          uint16     `align:"pad2"`
	SockCookie uint64     `align:"sock_cookie"`
	CgroupId   uint64     `align:"cgroup_id"`
	DstIP      types.IPv6 `align:"dst_ip"`
}

// Dump prints the message according to the verbosity level specified
func (t *TraceSockNotify) Dump(args *api.DumpArgs) {
	// Currently only printed with the debug option. Extend it to info and json.
	// GH issue: https://github.com/cilium/cilium/issues/21510
	if args.Verbosity == api.DEBUG {
		fmt.Fprintf(args.Buf, "%s [%s] cgroup_id: %d sock_cookie: %d, dst [%s]:%d %s \n",
			args.CpuPrefix, t.XlatePointStr(), t.CgroupId, t.SockCookie, t.IP(), t.DstPort, t.L4ProtoStr())
	}
}

// Decode decodes the message in 'data' into the struct.
func (t *TraceSockNotify) Decode(data []byte) error {
	if l := len(data); l < TraceSockNotifyLen {
		return fmt.Errorf("unexpected TraceSockNotify data length, expected %d but got %d", TraceSockNotifyLen, l)
	}

	t.Type = data[0]
	t.XlatePoint = data[1]
	t.L4Proto = data[2]
	t.Flags = data[3]
	t.DstPort = binary.NativeEndian.Uint16(data[4:6])
	t.SockCookie = binary.NativeEndian.Uint64(data[8:16])
	t.CgroupId = binary.NativeEndian.Uint64(data[16:24])
	copy(t.DstIP[:], data[24:40])

	return nil
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
