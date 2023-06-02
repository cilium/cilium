// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import "github.com/cilium/cilium/pkg/hive/cell"

// BpfMap defines the base interface every BPF map needs to implement.
//
// Its main purpose is to register a BPF map via value group `bpf-maps`. See [MapOut].
type BpfMap interface{}

// MapOut ensures that maps are created before the datapath loader
// is invoked.
type MapOut[T any] struct {
	cell.Out

	Map    T
	BpfMap BpfMap `group:"bpf-maps"`
}

func NewMapOut[T any](m T) MapOut[T] {
	return MapOut[T]{Map: m, BpfMap: m}
}
