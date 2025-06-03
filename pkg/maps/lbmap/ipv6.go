// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// HealthProbe6MapName is the health datapath map name
	HealthProbe6MapName = maps.HealthProbe6MapName

	// SockRevNat6MapName is the BPF map name.
	SockRevNat6MapName = maps.SockRevNat6MapName

	// SockRevNat6MapSize is the maximum number of entries in the BPF map.
	SockRevNat6MapSize = maps.SockRevNat6MapSize

	// Service6MapV2Name is the name of the IPv6 LB Services v2 BPF map.
	Service6MapV2Name = maps.Service6MapV2Name
	// Backend6MapName is the name of the IPv6 LB backends BPF map.
	Backend6MapName = maps.Backend6MapName
	// Backend6MapV2Name is the name of the IPv6 LB backends v2 BPF map.
	Backend6MapV2Name = maps.Backend6MapV2Name
	// Backend6MapV3Name is the name of the IPv6 LB backends v3 BPF map.
	Backend6MapV3Name = maps.Backend6MapV3Name
	// RevNat6MapName is the name of the IPv6 LB reverse NAT BPF map.
	RevNat6MapName = maps.RevNat6MapName
)

type (
	Service6Key   = maps.Service6Key
	Service6Value = maps.Service6Value

	Backend6Key   = maps.Backend6Key
	Backend6Value = maps.Backend6Value

	Backend6KeyV3   = maps.Backend6KeyV3
	Backend6ValueV3 = maps.Backend6ValueV3

	RevNat6Key   = maps.RevNat6Key
	RevNat6Value = maps.RevNat6Value

	SockRevNat6Key   = maps.SockRevNat6Key
	SockRevNat6Value = maps.SockRevNat6Value
)

var (
	NewService6Key = maps.NewService6Key

	NewBackend6KeyV3   = maps.NewBackend6KeyV3
	NewBackend6V2      = maps.NewBackend6V2
	NewBackend6V3      = maps.NewBackend6V3
	NewBackend6Value   = maps.NewBackend6Value
	NewBackend6ValueV3 = maps.NewBackend6ValueV3

	NewRevNat6Key     = maps.NewRevNat6Key
	NewSockRevNat6Key = maps.NewSockRevNat6Key

	SizeofSockRevNat6Key   = maps.SizeofSockRevNat6Key
	SizeofSockRevNat6Value = maps.SizeofSockRevNat6Value

	// MaxSockRevNat6MapEntries is the maximum number of entries in the BPF
	// map. It is set by Init(), but unit tests use the initial value below.
	MaxSockRevNat6MapEntries = SockRevNat6MapSize

	// The following BPF maps are initialized in initSVC().

	// Service6MapV2 is the IPv6 LB Services v2 BPF map.
	Service6MapV2 *bpf.Map
	// Backend6Map is the IPv6 LB backends BPF map.
	Backend6Map *bpf.Map
	// Backend6MapV2 is the IPv6 LB backends v2 BPF map.
	Backend6MapV2 *bpf.Map
	// Backend6MapV3 is the IPv6 LB backends v3 BPF map.
	Backend6MapV3 *bpf.Map
	// RevNat6Map is the IPv6 LB reverse NAT BPF map.
	RevNat6Map *bpf.Map
	// SockRevNat6Map is the IPv6 LB sock reverse NAT BPF map.
	SockRevNat6Map *bpf.Map
)

// CreateSockRevNat6Map creates the reverse NAT sock map.
func CreateSockRevNat6Map(registry *metrics.Registry) error {
	SockRevNat6Map = bpf.NewMap(SockRevNat6MapName,
		ebpf.LRUHash,
		&SockRevNat6Key{},
		&SockRevNat6Value{},
		MaxSockRevNat6MapEntries,
		0,
	).WithPressureMetric(registry)
	return SockRevNat6Map.OpenOrCreate()
}
