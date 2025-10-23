// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighborsmap

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"neighbors-map",
	"Neighbors Map",
	cell.Provide(NewMap),
)

func NewMap(
	lifecycle cell.Lifecycle,
	mapSpecRegistry *registry.MapSpecRegistry,
	kprConfig kpr.KPRConfig,
) (bpf.MapOut[*NeighborsMap], error) {
	err := mapSpecRegistry.ModifyMapSpec(Map4Name, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(option.Config.NeighMapEntriesGlobal)
		return nil
	})
	if err != nil {
		return bpf.MapOut[*NeighborsMap]{}, err
	}

	err = mapSpecRegistry.ModifyMapSpec(Map6Name, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(option.Config.NeighMapEntriesGlobal)
		return nil
	})
	if err != nil {
		return bpf.MapOut[*NeighborsMap]{}, err
	}

	neighborsMap := &NeighborsMap{}

	if !kprConfig.KubeProxyReplacement {
		return bpf.NewMapOut(neighborsMap), nil
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if option.Config.EnableIPv4 {
				spec4, err := mapSpecRegistry.Get(Map4Name)
				if err != nil {
					return err
				}

				neighborsMap.IPv4Map = bpf.NewMap(spec4, &Key4{}, &Value{})

				if err := neighborsMap.IPv4Map.OpenOrCreate(); err != nil {
					return err
				}
			}

			if option.Config.EnableIPv6 {
				spec6, err := mapSpecRegistry.Get(Map6Name)
				if err != nil {
					return err
				}

				neighborsMap.IPv6Map = bpf.NewMap(spec6, &Key6{}, &Value{})

				if err := neighborsMap.IPv6Map.OpenOrCreate(); err != nil {
					return err
				}
			}
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			if option.Config.EnableIPv4 {
				neighborsMap.IPv4Map.Close()
			}

			if option.Config.EnableIPv6 {
				neighborsMap.IPv6Map.Close()
			}
			return nil
		},
	})

	return bpf.NewMapOut(neighborsMap), nil
}
