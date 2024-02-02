// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb/index"
)

// Route represents a single route
type Route struct {
	VRFPrefix
	NextHop NextHop
	Proto   Proto
	Owner   Owner
}

// RouteID uniquely identifies route within the RIB
type RouteID struct {
	VRF    uint32
	Prefix netip.Prefix
	Owner  Owner
}

// Key generates an index.Key for RouteID
func (id RouteID) Key() index.Key {
	key := index.Uint32(id.VRF)
	key = append(key, index.NetIPPrefix(id.Prefix)...)
	key = append(key, index.Uint16(id.Owner.ID)...)
	key = append(key, 0)
	return key
}

// VRFPrefix is a key to list routes that have the same VRF and Prefix, but
// have different owners.
type VRFPrefix struct {
	VRF    uint32
	Prefix netip.Prefix
}

// Key generates an index.Key for vrfPrefix
func (vp VRFPrefix) Key() index.Key {
	key := index.Uint32(vp.VRF)
	key = append(key, index.NetIPPrefix(vp.Prefix)...)
	key = append(key, 0)
	return key
}

// NextHop is an interface that all NextHop objects must implement
type NextHop interface {
	// Kind is a numeric ID of the nexthop kind. Each NextHop kind must have unique ID.
	Kind() NextHopKind
	// Name is a human-readable name of the nexthop kind.
	Name() string
}

type NextHopKind uint16

const (
	NextHopIPv4 NextHopKind = iota
	NextHopIPv6
)

// Owner represents an owner of the route
type Owner struct {
	// ID is an ID of the owner. Each owner must have a unique ID.
	ID uint16
	// Name is a human-readable name of the owner.
	Name string
}

// Proto represents a protocol that imports the route
type Proto struct {
	// Kind is a numeric ID of the protocol. Each protocol kind must have a unique ID.
	Kind ProtoKind
	// Name is a human-readable name of the protocol.
	Name string
	// Distance is a distance of this protocol. When more than two
	// protocols install exactly the same routes, the route installed by
	// the protocol with lower distance takes presedence.
	Distance uint16
}

type ProtoKind uint16

const (
	ProtoKindK8s NextHopKind = iota
	ProtoKindBGP
)
