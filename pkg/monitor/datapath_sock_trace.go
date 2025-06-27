// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/byteorder"
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
	Type       uint8      // 1 byte
	XlatePoint uint8      // 1 byte
	DstIP      types.IPv6 // 16 bytes
	DstPort    uint16     // 2 bytes
	L4Proto    uint8      // 1 byte
	Flags      uint8      // 1 byte
	_          [2]byte    // 2 bytes (explicit padding to avoid automatic padding)
	SockCookie uint64     // 8 bytes
	CgroupId   uint64     // 8 bytes
}

// DecodeTraceSockNotify will decode 'data' into the provided TraceSockNotify structure
func DecodeTraceSockNotify(data []byte, sock *TraceSockNotify) error {
	return sock.decodeTraceSockNotify(data)
}

func (t *TraceSockNotify) decodeTraceSockNotify(data []byte) error {
	if l := len(data); l < TraceSockNotifyLen {
		return fmt.Errorf("unexpected TraceSockNotify data length, expected %d but got %d", TraceSockNotifyLen, l)
	}

	t.Type = data[0]
	t.XlatePoint = data[1]
	copy(t.DstIP[:], data[2:18])
	t.DstPort = byteorder.Native.Uint16(data[18:20])
	t.L4Proto = data[20]
	t.Flags = data[21]
	t.SockCookie = byteorder.Native.Uint64(data[24:32])
	t.CgroupId = byteorder.Native.Uint64(data[32:40])

	return nil
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
