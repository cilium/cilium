// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

// SharedPolicyKey identifies entries in the node-scoped shared policy map.
//
// The EndpointGroupPrefix currently mirrors the endpoint ID, but is preserved
// as a prefix field to allow future grouping strategies without changing the
// datapath key layout.
//
// Must be kept in sync with struct shared_policy_key in the datapath once the
// map is wired up.
type SharedPolicyKey struct {
	EndpointGroupPrefix uint32
	Identity            identity.NumericIdentity
	Direction           trafficdirection.TrafficDirection
	Nexthdr             u8proto.U8proto
	DestPortNetwork     uint16
	PrefixLen           uint8
	ProxyPort           uint16
	AuthType            uint8
	Deny                uint8
	Precedence          uint32
	Cookie              uint32
}

// SharedPolicyEntry reuses the existing PolicyEntry layout to avoid duplicating
// datapath definitions.
type SharedPolicyEntry = PolicyEntry

// OverlayPrivateEntry pairs a policy key with its entry for private overrides.
// This allows the datapath to match traffic against specific private rules.
type OverlayPrivateEntry struct {
	Key   PolicyKey
	Entry PolicyEntry
}

// OverlayEntry captures the per-endpoint overlay that augments the shared
// policy map. SharedHandles reference entries in the shared map, while Private
// contains endpoint-scoped overrides that should bypass sharing.
type OverlayEntry struct {
	SharedHandles []uint32
	Private       []OverlayPrivateEntry
}

// The maximum overlay dimensions are compiled into the BPF value layout. They
// are intentionally small defaults that can be tuned via build options once the
// datapath wiring is added.
const (
	DefaultMaxSharedRefs      = 16
	DefaultMaxPrivateOverride = 8
)

// OverlayEntryBPF mirrors struct overlay_entry in the datapath. The struct
// needs a fixed-size layout so the arrays are backed by constants rather than
// runtime configuration.
type OverlayEntryBPF struct {
	SharedRefCount   uint8
	PrivateCount     uint8
	Pad              [2]uint8
	SharedRefs       [DefaultMaxSharedRefs]uint32
	PrivateOverrides [DefaultMaxPrivateOverride]OverlayPrivateEntry
}

// Clamp converts the high-level OverlayEntry into the fixed-size BPF-friendly
// representation, truncating any entries that exceed the configured maximums.
func (o OverlayEntry) Clamp() OverlayEntryBPF {
	return o.ClampWith(DefaultMaxSharedRefs, DefaultMaxPrivateOverride)
}

// ClampWith converts to OverlayEntryBPF while honoring explicit limits. This
// helper is primarily used by tests to emulate kernels compiled with different
// bounds without rebuilding the entire daemon.
func (o OverlayEntry) ClampWith(maxShared, maxPrivate int) OverlayEntryBPF {
	var out OverlayEntryBPF

	shared := len(o.SharedHandles)
	if shared > maxShared {
		shared = maxShared
	}
	out.SharedRefCount = uint8(shared)
	for i := 0; i < shared; i++ {
		out.SharedRefs[i] = o.SharedHandles[i]
	}

	priv := len(o.Private)
	if priv > maxPrivate {
		priv = maxPrivate
	}
	out.PrivateCount = uint8(priv)
	for i := 0; i < priv; i++ {
		out.PrivateOverrides[i] = o.Private[i]
	}

	return out
}
