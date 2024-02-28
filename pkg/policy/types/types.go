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
	// NextHdr is the protocol which is allowed.
	Nexthdr uint8
	// TrafficDirection indicates in which direction Identity is allowed
	// communication (egress or ingress).
	TrafficDirection uint8
}

// String returns a string representation of the Key
func (k Key) String() string {
	return "Identity=" + strconv.FormatUint(uint64(k.Identity), 10) +
		",DestPort=" + strconv.FormatUint(uint64(k.DestPort), 10) +
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

// PortProtoIsBroader returns true if the receiver Key has broader
// port-protocol than the argument Key. That is a port-protocol
// that covers the argument Key's port-protocol and is larger.
// An equal port-protocol will return false.
func (k Key) PortProtoIsBroader(c Key) bool {
	return k.DestPort == 0 && c.DestPort != 0 ||
		k.Nexthdr == 0 && c.Nexthdr != 0
}

// PortProtoIsEqual returns true if the port-protocols of the
// two keys are exactly equal.
func (k Key) PortProtoIsEqual(c Key) bool {
	return k.DestPort == c.DestPort && k.Nexthdr == c.Nexthdr
}

// PrefixLength returns the prefix lenth of the key
// for indexing it.
func (k Key) PrefixLength() uint {
	p := MapStatePrefixLen
	if k.DestPort == 0 {
		p -= 16
		// We can only mask Nexthdr
		// if DestPort is also masked.
		if k.Nexthdr == 0 {
			p -= 8
		}
	}
	return p
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
