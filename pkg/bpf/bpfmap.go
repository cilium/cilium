// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/hive"
)

// MapOut ensures that BPF maps are created before the datapath loader Cell is
// invoked.
type MapOut[T any] struct {
	cell.Out

	Map T

	// loader.Cell depends on the bpf-maps value group to ensure it is started
	// after all maps have been started. Values provided to a value group cannot
	// be received as regular Cell arguments, so we need to output it twice.
	Group any `group:"bpf-maps"`
}

// NewMapOut returns a MapOut containing the provided map. Use this in the
// Provide function of a Cell to make a BPF map available to other Cells.
func NewMapOut[T any](m T) MapOut[T] {
	return MapOut[T]{Map: m, Group: m}
}

// MapGroup is used as a Cell argument to depend on all BPF maps created by the
// agent.
//
// Depend on this type if you want to ensure that your Cell is started after all
// BPF maps have been created.
type MapGroup struct {
	cell.In

	Group []any `group:"bpf-maps"`
}

// MaybeMapOut is returned by a Provide function when a map is only created when
// certain features are enabled. Use [MaybeMap] to receive an optional map in
// another Cell.
type MaybeMapOut[T any] struct {
	cell.Out

	Map hive.Optional[T]

	Group any `group:"bpf-maps"`
}

// SomeMap returns a [MaybeMapOut] containing the provided map. Use this in the
// Provide function of a Cell to make a BPF map available to other Cells.
//
// This is used when a map is only created when certain features are enabled. If
// the map is not enabled, return [NoneMap] instead.
func SomeMap[T any](m T) MaybeMapOut[T] {
	om := hive.Some(m)
	return MaybeMapOut[T]{Map: om, Group: om}
}

// NoneMap returns an empty [MaybeMapOut]. Return this instead of nil from the
// Provide function of a Cell to indicate that a BPF map was disabled by runtime
// configuration.
func NoneMap[T any]() MaybeMapOut[T] {
	n := hive.None[T]()
	return MaybeMapOut[T]{Map: n, Group: n}
}

// MaybeMap is used to receive BPF maps provided by other Cells using
// [MaybeMapOut]. Some maps are only provided when certain features are enabled.
//
// Call [MaybeMap.Get] and check if the returned boolean value is true before
// accessing the first return value.
type MaybeMap[T any] struct {
	cell.In

	// Do not access this field directly, use [MaybeMap.Get].
	hive.Optional[T]
}

// Get returns the map provided by another Cell and a boolean value indicating
// whether the map is enabled or not.
func (mi MaybeMap[T]) Get() (T, bool) {
	return mi.Optional.Get()
}
