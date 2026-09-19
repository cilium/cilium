// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package typeurl defines the fixed set of xDS resource types managed by the
// Cilium ADS cache. Protocol inputs remain strings and are converted at the
// boundary; internal state uses Index and Set so it cannot admit unknown types.
package typeurl

import (
	"iter"
	"math/bits"

	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

const (
	NetworkPolicyURL      = "type.googleapis.com/cilium.NetworkPolicy"
	NetworkPolicyHostsURL = "type.googleapis.com/cilium.NetworkPolicyHosts"
)

// Index identifies one resource type managed by the Cilium ADS cache.
type Index uint8

const (
	Endpoint Index = iota
	Cluster
	Route
	Listener
	Secret
	NetworkPolicy
	NetworkPolicyHosts
	Count
)

// Slots provides fixed storage for every supported resource type.
type Slots[T any] [Count]T

// Map stores sparse values for the fixed set of supported resource types.
// Unlike a Go map it allocates no backing storage; presence is tracked by the
// accompanying bit set so a stored value may itself be the zero value.
type Map[T any] struct {
	values  Slots[T]
	present Set
}

// NewMap returns an initialized empty fixed resource-type map. This preserves
// APIs which distinguish an omitted map from an explicitly empty one.
func NewMap[T any]() Map[T] {
	return Map[T]{present: NewSet()}
}

var urls = [...]string{
	Endpoint:           envoy_resource.EndpointType,
	Cluster:            envoy_resource.ClusterType,
	Route:              envoy_resource.RouteType,
	Listener:           envoy_resource.ListenerType,
	Secret:             envoy_resource.SecretType,
	NetworkPolicy:      NetworkPolicyURL,
	NetworkPolicyHosts: NetworkPolicyHostsURL,
}

// FromURL converts a protocol TypeURL to its internal index. Unknown TypeURLs
// are deliberately rejected rather than sharing an array slot.
func FromURL(typeURL string) (Index, bool) {
	switch typeURL {
	case envoy_resource.EndpointType:
		return Endpoint, true
	case envoy_resource.ClusterType:
		return Cluster, true
	case envoy_resource.RouteType:
		return Route, true
	case envoy_resource.ListenerType:
		return Listener, true
	case envoy_resource.SecretType:
		return Secret, true
	case NetworkPolicyURL:
		return NetworkPolicy, true
	case NetworkPolicyHostsURL:
		return NetworkPolicyHosts, true
	default:
		return Count, false
	}
}

// URL returns the protocol TypeURL for index, or an empty string for an invalid
// index.
func (index Index) URL() string {
	if index >= Count {
		return ""
	}
	return urls[index]
}

// Indices iterates over every supported resource type in snapshot order.
func Indices() iter.Seq[Index] {
	return func(yield func(Index) bool) {
		for index := range Count {
			if !yield(index) {
				return
			}
		}
	}
}

// Set is a fixed-size resource-type set. The zero value is unspecified rather
// than an initialized empty set, preserving the distinction used by snapshot
// generation between "regenerate everything" and "nothing changed".
type Set struct {
	bits  uint8
	known bool
}

// NewSet returns an initialized set containing indices.
func NewSet(indices ...Index) Set {
	set := Set{known: true}
	for _, index := range indices {
		set.Insert(index)
	}
	return set
}

// All returns an initialized set containing every supported resource type.
func All() Set {
	return Set{bits: uint8(1<<Count) - 1, known: true}
}

// Known reports whether the set was initialized.
func (set Set) Known() bool {
	return set.known
}

// Empty reports whether the set contains no resource types.
func (set Set) Empty() bool {
	return set.bits == 0
}

// Len returns the number of contained resource types.
func (set Set) Len() int {
	return bits.OnesCount8(set.bits)
}

// Has reports whether index is contained in the set.
func (set Set) Has(index Index) bool {
	return index < Count && set.bits&(1<<index) != 0
}

// Insert inserts index into the set. Invalid indices are ignored.
func (set *Set) Insert(index Index) {
	set.known = true
	if index < Count {
		set.bits |= 1 << index
	}
}

// Remove removes index from the set.
func (set *Set) Remove(index Index) {
	if index < Count {
		set.bits &^= 1 << index
	}
}

// Union returns the initialized union of set and other.
func (set Set) Union(other Set) Set {
	return Set{bits: set.bits | other.bits, known: set.known || other.known}
}

// Members iterates over the contained indices in snapshot order.
func (set Set) Members() iter.Seq[Index] {
	return func(yield func(Index) bool) {
		for index := range Count {
			if set.Has(index) && !yield(index) {
				return
			}
		}
	}
}

// Set stores value for index. Invalid indices are ignored.
func (values *Map[T]) Set(index Index, value T) {
	if index >= Count {
		return
	}
	values.values[index] = value
	values.present.Insert(index)
}

// Get returns the stored value and whether index is present.
func (values Map[T]) Get(index Index) (T, bool) {
	if index < Count && values.present.Has(index) {
		return values.values[index], true
	}
	var zero T
	return zero, false
}

// Has reports whether index has a stored value.
func (values Map[T]) Has(index Index) bool {
	return values.present.Has(index)
}

// Known reports whether the map was initialized or has ever contained a key.
func (values Map[T]) Known() bool {
	return values.present.Known()
}

// Remove removes the value stored for index.
func (values *Map[T]) Remove(index Index) {
	if index >= Count || !values.present.Has(index) {
		return
	}
	var zero T
	values.values[index] = zero
	values.present.Remove(index)
}

// Empty reports whether no values are present.
func (values Map[T]) Empty() bool {
	return values.present.Empty()
}

// Len returns the number of present values.
func (values Map[T]) Len() int {
	return values.present.Len()
}

// Keys iterates over present resource types in snapshot order.
func (values Map[T]) Keys() iter.Seq[Index] {
	return values.present.Members()
}

// All iterates over present resource types and values in snapshot order.
func (values Map[T]) All() iter.Seq2[Index, T] {
	return func(yield func(Index, T) bool) {
		for index := range values.present.Members() {
			if !yield(index, values.values[index]) {
				return
			}
		}
	}
}
