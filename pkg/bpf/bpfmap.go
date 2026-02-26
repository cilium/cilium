// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import "github.com/cilium/hive/cell"

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
