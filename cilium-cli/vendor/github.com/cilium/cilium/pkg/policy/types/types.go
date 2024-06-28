// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"math/bits"
	"strconv"

	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// MapStatePrefixLen is the length, in bits, of the Key when converted
// to binary minus the sizeof the identity field (which is not indexed).
const MapStatePrefixLen = uint(32)

// Key is the userspace representation of a policy key in BPF. It is
// intentionally duplicated from pkg/maps/policymap to avoid pulling in the
// BPF dependency to this package.
type Key struct {
	// Identity is the numeric identity to / from which traffic is allowed.
	Identity uint32
	// DestPort is the port at L4 to / from which traffic is allowed, in
	// host-byte order.
	DestPort uint16
	// InvertedPortMask is the mask that should be applied to the DestPort to
	// define a range of ports for the policy-key, encoded as the bitwise inverse
	// of its true/useful value. This is done so that the default value of the
	// Key is a full port mask (that is, "0" represents 0xffff), as that is
	// the most likely value to be used. InvertedPortMask is also, conveniently,
	// the number or ports on top of DestPort that define that range. That is
	// the end port is equal to the DestPort added to the InvertedPortMask.
	//
	// It is **not** the prefix that is applied for the BPF key entries.
	// That value is calculated in the maps/policymap package.
	//
	// For example:
	// range 2-3 would be DestPort:2 and InvertedPortMask:0x1 (i.e 0xfffe)
	// range 32768-49151 would be DestPort:32768 and InvertedPortMask:0x3fff (i.e. 0xc000)
	InvertedPortMask uint16
	// NextHdr is the protocol which is allowed.
	Nexthdr uint8
	// TrafficDirection indicates in which direction Identity is allowed
	// communication (egress or ingress).
	TrafficDirection uint8
}

// PortMask returns the bitwise mask that should be applied
// to the DestPort.
func (k Key) PortMask() uint16 {
	return ^k.InvertedPortMask
}

// String returns a string representation of the Key
func (k Key) String() string {
	dPort := strconv.FormatUint(uint64(k.DestPort), 10)
	if k.DestPort != 0 && k.InvertedPortMask != 0 {
		dPort += "-" + strconv.FormatUint(uint64(k.DestPort+k.InvertedPortMask), 10)
	}
	return "Identity=" + strconv.FormatUint(uint64(k.Identity), 10) +
		",DestPort=" + dPort +
		",Nexthdr=" + strconv.FormatUint(uint64(k.Nexthdr), 10) +
		",TrafficDirection=" + strconv.FormatUint(uint64(k.TrafficDirection), 10)
}

// IsIngress returns true if the key refers to an ingress policy key
func (k Key) IsIngress() bool {
	return k.TrafficDirection == trafficdirection.Ingress.Uint8()
}

// IsEgress returns true if the key refers to an egress policy key
func (k Key) IsEgress() bool {
	return k.TrafficDirection == trafficdirection.Egress.Uint8()
}

// EndPort returns the end-port of the Key based on the Mask.
func (k Key) EndPort() uint16 {
	return k.DestPort + k.InvertedPortMask
}

// PortProtoIsBroader returns true if the receiver Key has broader
// port-protocol than the argument Key. That is a port-protocol
// that covers the argument Key's port-protocol and is larger.
// An equal port-protocol will return false.
func (k Key) PortProtoIsBroader(c Key) bool {
	if k.Nexthdr == 0 && c.Nexthdr != 0 {
		return k.PortIsEqual(c) || k.PortIsBroader(c)
	}
	return k.Nexthdr == c.Nexthdr && k.PortIsBroader(c)
}

// PortProtoIsEqual returns true if the port-protocols of the
// two keys are exactly equal.
func (k Key) PortProtoIsEqual(c Key) bool {
	return k.DestPort == c.DestPort &&
		k.InvertedPortMask == c.InvertedPortMask &&
		k.Nexthdr == c.Nexthdr
}

// PortIsBroader returns true if the receiver Key's
// port range covers the argument Key's port range,
// but returns false if they are equal.
func (k Key) PortIsBroader(c Key) bool {
	if k.DestPort == 0 && c.DestPort != 0 {
		return true
	}
	if k.DestPort != 0 && c.DestPort == 0 {
		return false
	}
	kEP := k.EndPort()
	cEP := c.EndPort()
	return k.DestPort <= c.DestPort && kEP >= cEP &&
		// The port ranges cannot be exactly equal.
		(k.DestPort != c.DestPort || kEP != cEP)
}

// PortIsEqual returns true if the port ranges
// between the two keys are exactly equal.
func (k Key) PortIsEqual(c Key) bool {
	return k.DestPort == c.DestPort &&
		k.InvertedPortMask == c.InvertedPortMask
}

// PrefixLength returns the prefix lenth of the key
// for indexing it for the userspace cache (not the
// BPF map or datapath).
func (k Key) PrefixLength() uint {
	keyPrefix := MapStatePrefixLen
	portPrefix := uint(16)
	if k.DestPort != 0 {
		// It is not possible for k.InvertedPortMask
		// to be incorrectly set, but even if
		// it was the default value of "0" is
		// what we want.
		portPrefix = uint(bits.TrailingZeros16(k.PortMask()))
	}
	keyPrefix -= portPrefix
	// If the port is fully wildcarded then
	// we can also wildcard the protocol
	// (if it is also wildcarded).
	if portPrefix == 16 && k.Nexthdr == 0 {
		keyPrefix -= 8
	}
	return keyPrefix
}

// CommonPrefix implements the CommonPrefix method for the
// bitlpm.Key interface. Identity is not indexed and is instead,
// saved as a simple map per TrafficDirection-Protocol-Port index
// key.
func (k Key) CommonPrefix(b Key) uint {
	v := bits.LeadingZeros8(k.TrafficDirection ^ b.TrafficDirection)
	if v != 8 {
		return uint(v)
	}
	v += bits.LeadingZeros8(k.Nexthdr ^ b.Nexthdr)
	if v != 16 {
		return uint(v)
	}
	return uint(v + bits.LeadingZeros16(k.DestPort^b.DestPort))
}

// BitValueAt implements the BitValueAt method for the
// bitlpm.Key interface.
func (k Key) BitValueAt(i uint) uint8 {
	if i < 8 {
		return min(k.TrafficDirection&(1<<(7-i)), 1)
	}
	if i < 16 {
		return min(k.Nexthdr&(1<<(7-(i-8))), 1)
	}
	return uint8(min(k.DestPort&(1<<(15-(i-16))), 1))
}

// Value implements the Value method for the
// bitlpm.Key interface.
func (k Key) Value() Key {
	return k
}

type Keys map[Key]struct{}
