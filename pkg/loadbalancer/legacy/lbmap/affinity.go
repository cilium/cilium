// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	AffinityMatchMapName = maps.AffinityMatchMapName
	Affinity4MapName     = maps.Affinity4MapName
	Affinity6MapName     = maps.Affinity6MapName
)

type (
	AffinityMatchKey   = maps.AffinityMatchKey
	AffinityMatchValue = maps.AffinityMatchValue
	Affinity4Key       = maps.Affinity4Key
	Affinity6Key       = maps.Affinity6Key
	AffinityValue      = maps.AffinityValue
)

var (
	NewAffinityMatchKey = maps.NewAffinityMatchKey

	// AffinityMatchMap is the BPF map to implement session affinity.
	AffinityMatchMap *bpf.Map
	Affinity4Map     *bpf.Map
	Affinity6Map     *bpf.Map
)

// initAffinity creates the BPF maps for implementing session affinity.
func initAffinity(registry *metrics.Registry, params InitParams) {
	AffinityMapMaxEntries = params.AffinityMapMaxEntries

	AffinityMatchMap = bpf.NewMap(
		AffinityMatchMapName,
		ebpf.Hash,
		&AffinityMatchKey{},
		&AffinityMatchValue{},
		AffinityMapMaxEntries,
		0,
	).WithCache().WithPressureMetric(registry).
		WithEvents(option.Config.GetEventBufferConfig(AffinityMatchMapName))

	if params.IPv4 {
		Affinity4Map = bpf.NewMap(
			Affinity4MapName,
			ebpf.LRUHash,
			&Affinity4Key{},
			&AffinityValue{},
			AffinityMapMaxEntries,
			0,
		)
	}

	if params.IPv6 {
		Affinity6Map = bpf.NewMap(
			Affinity6MapName,
			ebpf.LRUHash,
			&Affinity6Key{},
			&AffinityValue{},
			AffinityMapMaxEntries,
			0,
		)
	}
}
