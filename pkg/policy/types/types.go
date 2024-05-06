// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"strconv"

	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

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

type Keys map[Key]struct{}
