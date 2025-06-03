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
	// HealthProbe4MapName is the health datapath map name
	HealthProbe4MapName = maps.HealthProbe4MapName

	// SockRevNat4MapName is the BPF map name.
	SockRevNat4MapName = maps.SockRevNat4MapName

	// SockRevNat4MapSize is the maximum number of entries in the BPF map.
	SockRevNat4MapSize = maps.SockRevNat4MapSize

	// Service4MapV2Name is the name of the IPv4 LB Services v2 BPF map.
	Service4MapV2Name = maps.Service4MapV2Name
	// Backend4MapName is the name of the IPv4 LB backends BPF map.
	Backend4MapName = maps.Backend4MapName
	// Backend4MapV2Name is the name of the IPv4 LB backends v2 BPF map.
	Backend4MapV2Name = maps.Backend4MapV2Name
	// Backend4MapV3Name is the name of the IPv4 LB backends v3 BPF map.
	Backend4MapV3Name = maps.Backend4MapV3Name
	// RevNat4MapName is the name of the IPv4 LB reverse NAT BPF map.
	RevNat4MapName = maps.RevNat4MapName
)

type (
	RevNat4Key   = maps.RevNat4Key
	RevNat4Value = maps.RevNat4Value

	Service4Key   = maps.Service4Key
	Service4Value = maps.Service4Value

	Backend4Key   = maps.Backend4Key
	Backend4KeyV3 = maps.Backend4KeyV3

	Backend4Value   = maps.Backend4Value
	Backend4ValueV3 = maps.Backend4ValueV3
)

var (
	NewService4Key = maps.NewService4Key

	NewBackend4KeyV3   = maps.NewBackend4KeyV3
	NewBackend4V2      = maps.NewBackend4V2
	NewBackend4V3      = maps.NewBackend4V3
	NewBackend4Value   = maps.NewBackend4Value
	NewBackend4ValueV3 = maps.NewBackend4ValueV3

	NewRevNat4Key = maps.NewRevNat4Key
)

var (
	// MaxSockRevNat4MapEntries is the maximum number of entries in the BPF
	// map. It is set by Init(), but unit tests use the initial value below.
	MaxSockRevNat4MapEntries = SockRevNat4MapSize

	// The following BPF maps are initialized in initSVC().

	// Service4MapV2 is the IPv4 LB Services v2 BPF map.
	Service4MapV2 *bpf.Map
	// Backend4Map is the IPv4 LB backends BPF map.
	Backend4Map *bpf.Map
	// Backend4MapV2 is the IPv4 LB backends v2 BPF map.
	Backend4MapV2 *bpf.Map
	// Backend4MapV2 is the IPv4 LB backends v2 BPF map.
	Backend4MapV3 *bpf.Map
	// RevNat4Map is the IPv4 LB reverse NAT BPF map.
	RevNat4Map *bpf.Map
	// SockRevNat4Map is the IPv4 LB sock reverse NAT BPF map.
	SockRevNat4Map *bpf.Map
)

// initSVC constructs the IPv4 & IPv6 LB BPF maps used for Services. The maps
// have their maximum entries configured. Note this does not create or open the
// maps; it simply constructs the objects.
func initSVC(registry *metrics.Registry, params InitParams) {
	ServiceMapMaxEntries = params.ServiceMapMaxEntries
	ServiceBackEndMapMaxEntries = params.BackEndMapMaxEntries
	RevNatMapMaxEntries = params.RevNatMapMaxEntries

	if params.IPv4 {
		Service4MapV2 = bpf.NewMap(Service4MapV2Name,
			ebpf.Hash,
			&Service4Key{},
			&Service4Value{},
			ServiceMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Service4MapV2Name))
		Backend4Map = bpf.NewMap(Backend4MapName,
			ebpf.Hash,
			&Backend4Key{},
			&Backend4Value{},
			ServiceBackEndMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Backend4MapName))
		Backend4MapV2 = bpf.NewMap(Backend4MapV2Name,
			ebpf.Hash,
			&Backend4KeyV3{},
			&Backend4Value{},
			ServiceBackEndMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Backend4MapV2Name))
		Backend4MapV3 = bpf.NewMap(Backend4MapV3Name,
			ebpf.Hash,
			&Backend4KeyV3{},
			&Backend4ValueV3{},
			ServiceBackEndMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Backend4MapV3Name))
		RevNat4Map = bpf.NewMap(RevNat4MapName,
			ebpf.Hash,
			&RevNat4Key{},
			&RevNat4Value{},
			RevNatMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(RevNat4MapName))
	}

	if params.IPv6 {
		Service6MapV2 = bpf.NewMap(Service6MapV2Name,
			ebpf.Hash,
			&Service6Key{},
			&Service6Value{},
			ServiceMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Service6MapV2Name))
		Backend6Map = bpf.NewMap(Backend6MapName,
			ebpf.Hash,
			&Backend6Key{},
			&Backend6Value{},
			ServiceBackEndMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Backend6MapName))
		Backend6MapV2 = bpf.NewMap(Backend6MapV2Name,
			ebpf.Hash,
			&Backend6KeyV3{},
			&Backend6Value{},
			ServiceBackEndMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Backend6MapV2Name))
		Backend6MapV3 = bpf.NewMap(Backend6MapV3Name,
			ebpf.Hash,
			&Backend6KeyV3{},
			&Backend6ValueV3{},
			ServiceBackEndMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(Backend6MapV3Name))
		RevNat6Map = bpf.NewMap(RevNat6MapName,
			ebpf.Hash,
			&RevNat6Key{},
			&RevNat6Value{},
			RevNatMapMaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(RevNat6MapName))
	}
}

type (
	SockRevNat4Key   = maps.SockRevNat4Key
	SockRevNat4Value = maps.SockRevNat4Value
)

var NewSockRevNat4Key = maps.NewSockRevNat4Key

// CreateSockRevNat4Map creates the reverse NAT sock map.
func CreateSockRevNat4Map(registry *metrics.Registry) error {
	SockRevNat4Map = bpf.NewMap(SockRevNat4MapName,
		ebpf.LRUHash,
		&SockRevNat4Key{},
		&SockRevNat4Value{},
		MaxSockRevNat4MapEntries,
		0,
	).WithPressureMetric(registry)
	return SockRevNat4Map.OpenOrCreate()
}
