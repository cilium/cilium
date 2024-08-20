// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"math/bits"
	"strconv"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

// MapStatePrefixLen is the length, in bits, of the Key when converted
// to binary minus the sizeof the identity field (which is not indexed).
const MapStatePrefixLen = uint(32)

// Key is the userspace representation of a policy key in BPF. It is
// intentionally duplicated from pkg/maps/policymap to avoid pulling in the
// BPF dependency to this package.
type LPMKey struct {
	// bits contains the TrafficDirection in the highest bit and the port prefix length in the 5 lowest bits.
	bits uint8
	// NextHdr is the protocol which is allowed.
	Nexthdr u8proto.U8proto
	// DestPort is the port at L4 to / from which traffic is allowed, in
	// host-byte order.
	DestPort uint16
}

type Key struct {
	LPMKey
	// Identity is the numeric identity to / from which traffic is allowed.
	Identity identity.NumericIdentity
}

const (
	directionBitShift = 7
	directionBitMask  = uint8(1) << directionBitShift
)

//
// Key initialization utility functions
//

func EgressKey() Key {
	return Key{
		LPMKey: LPMKey{
			bits: 1 << directionBitShift,
		},
	}
}

func IngressKey() Key {
	return Key{
		LPMKey: LPMKey{
			bits: 0 << directionBitShift,
		},
	}
}

func KeyForDirection(direction trafficdirection.TrafficDirection) Key {
	return Key{
		LPMKey: LPMKey{
			bits: uint8(direction) << directionBitShift,
		},
	}
}

func (k Key) WithProto(proto u8proto.U8proto) Key {
	k.Nexthdr = proto
	return k
}

func (k Key) WithPort(port uint16) Key {
	k.DestPort = port
	k.bits &= directionBitMask

	if port != 0 {
		// non-wildcarded port
		k.bits |= 16
	}
	return k
}

func (k Key) WithPortPrefix(port uint16, prefixLen uint8) Key {
	if prefixLen > 16 || port != 0 && prefixLen == 0 {
		prefixLen = 16
	}
	// set up the port wildcard
	k.DestPort = port & (0xffff << (16 - prefixLen))
	k.bits = k.bits&directionBitMask | prefixLen
	return k
}

func (k Key) WithPortProto(proto u8proto.U8proto, port uint16) Key {
	return k.WithProto(proto).WithPort(port)
}

func (k Key) WithPortProtoPrefix(proto u8proto.U8proto, port uint16, prefixLen uint8) Key {
	return k.WithProto(proto).WithPortPrefix(port, prefixLen)
}

func (k Key) WithTCPPort(port uint16) Key {
	return k.WithPortProto(u8proto.TCP, port)
}

func (k Key) WithTCPPortPrefix(port uint16, prefixLen uint8) Key {
	return k.WithPortProtoPrefix(u8proto.TCP, port, prefixLen)
}

func (k Key) WithUDPPort(port uint16) Key {
	return k.WithPortProto(u8proto.UDP, port)
}

func (k Key) WithUDPPortPrefix(port uint16, prefixLen uint8) Key {
	return k.WithPortProtoPrefix(u8proto.UDP, port, prefixLen)
}
func (k Key) WithSCTPPort(port uint16) Key {
	return k.WithPortProto(u8proto.SCTP, port)
}

func (k Key) WithSCTPPortPrefix(port uint16, prefixLen uint8) Key {
	return k.WithPortProtoPrefix(u8proto.SCTP, port, prefixLen)
}

func (k Key) WithIdentity(nid identity.NumericIdentity) Key {
	k.Identity = nid
	return k
}

// TrafficDirection() returns the direction of the Key, 0 == ingress, 1 == egress
func (k LPMKey) TrafficDirection() trafficdirection.TrafficDirection {
	return trafficdirection.TrafficDirection(k.bits >> directionBitShift)
}

// PortPrefixLen returns the length of the bitwise mask that should be applied to the DestPort.
func (k LPMKey) PortPrefixLen() uint8 {
	return k.bits & ^directionBitMask
}

// String returns a string representation of the Key
func (k Key) String() string {
	dPort := strconv.FormatUint(uint64(k.DestPort), 10)
	if k.DestPort != 0 && k.PortPrefixLen() < 16 {
		dPort += "-" + strconv.FormatUint(uint64(k.DestPort+k.EndPort()), 10)
	}
	return "Identity=" + strconv.FormatUint(uint64(k.Identity), 10) +
		",DestPort=" + dPort +
		",Nexthdr=" + strconv.FormatUint(uint64(k.Nexthdr), 10) +
		",TrafficDirection=" + strconv.FormatUint(uint64(k.TrafficDirection()), 10)
}

// IsIngress returns true if the key refers to an ingress policy key
func (k LPMKey) IsIngress() bool {
	return k.TrafficDirection() == trafficdirection.Ingress
}

// IsEgress returns true if the key refers to an egress policy key
func (k LPMKey) IsEgress() bool {
	return k.TrafficDirection() == trafficdirection.Egress
}

// EndPort returns the end-port of the Key based on the Mask.
func (k LPMKey) EndPort() uint16 {
	return k.DestPort + uint16(0xffff)>>k.PortPrefixLen()
}

// PortProtoIsBroader returns true if the receiver Key has broader
// port-protocol than the argument Key. That is a port-protocol
// that covers the argument Key's port-protocol and is larger.
// An equal port-protocol will return false.
func (k Key) PortProtoIsBroader(c Key) bool {
	// Port is wildcarded when protocol is wildcarded
	return k.Nexthdr == 0 && c.Nexthdr != 0 || k.Nexthdr == c.Nexthdr && k.PortIsBroader(c)
}

// PortProtoIsEqual returns true if the port-protocols of the
// two keys are exactly equal.
func (k LPMKey) PortProtoIsEqual(c Key) bool {
	return k.Nexthdr == c.Nexthdr && k.PortIsEqual(c)
}

// PortIsBroader returns true if the receiver Key's
// port range covers the argument Key's port range,
// but returns false if they are equal.
func (k LPMKey) PortIsBroader(c Key) bool {
	// Broader port must have shorter prefix and a common part needs to be the same
	kPrefixLen := k.PortPrefixLen()
	cPrefixLen := c.PortPrefixLen()
	return kPrefixLen < cPrefixLen &&
		k.DestPort^c.DestPort&(uint16(0xffff)<<(16-kPrefixLen)) == 0
}

// PortIsEqual returns true if the port ranges
// between the two keys are exactly equal.
func (k LPMKey) PortIsEqual(c Key) bool {
	return k.DestPort == c.DestPort && k.bits<<1 == c.bits<<1 // ignore traffic direction
}

// PrefixLength returns the prefix lenth of the key
// for indexing it for the userspace cache (not the
// BPF map or datapath).
func (k LPMKey) PrefixLength() uint {
	if k.Nexthdr == 0 {
		return 1 // direction always specified
	}
	// 1 bit from direction bit + 8 bits for the protocol when `k.Nexthdr' != 0
	return 9 + uint(k.PortPrefixLen())
}

// CommonPrefix implements the CommonPrefix method for the
// bitlpm.Key interface. Identity is not indexed and is instead,
// saved as a simple map per TrafficDirection-Protocol-Port index
// key.
func (k LPMKey) CommonPrefix(b LPMKey) uint {
	// if direction bits are different then there is nothing in common
	if (k.bits^b.bits)>>directionBitShift != 0 {
		return 0
	}
	v := 1 + bits.LeadingZeros8(uint8(k.Nexthdr^b.Nexthdr))
	// if protocols are different then there is no need to look at the ports
	if v < 9 {
		return uint(v)
	}
	return uint(v + bits.LeadingZeros16(k.DestPort^b.DestPort))
}

// BitValueAt implements the BitValueAt method for the
// bitlpm.Key interface.
func (k LPMKey) BitValueAt(i uint) uint8 {
	switch {
	case i == 0:
		return k.bits >> directionBitShift
	case i < 9:
		return uint8((k.Nexthdr >> (8 - i)) & 1)
	default:
		return uint8(k.DestPort>>(24-i)) & 1
	}
}

// Value implements the Value method for the
// bitlpm.Key interface.
func (k LPMKey) Value() LPMKey {
	return k
}

type Keys map[Key]struct{}
