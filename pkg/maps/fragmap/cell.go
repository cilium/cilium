// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the fragmap.Map used to associate datagram
// fragments to the L4 ports of the datagram they belong to, in order to
// retrieve the full 5-tuple necessary to do L4-based lookups.
var Cell = cell.Module(
	"fragments-map",
	"Initializes fragments bpf map",

	// Provided to init at startup (The Loader depends on all maps via bpf.Mapout)
	cell.Provide(newFragMap),
	cell.Invoke(configure),
)

func configure(reg *registry.MapRegistry, daemonConfig *option.DaemonConfig) error {
	configureMap := func(name string) error {
		return reg.Modify(name, func(m *registry.MapSpecPatch) {
			m.MaxEntries = uint32(daemonConfig.FragmentsMapEntries)
			if daemonConfig.BPFDistributedLRU {
				m.Flags |= unix.BPF_F_NO_COMMON_LRU
			}
		})
	}

	if err := configureMap(mapNameIPv4); err != nil {
		return fmt.Errorf("configure %s: %w", mapNameIPv4, err)
	}
	if err := configureMap(mapNameIPv6); err != nil {
		return fmt.Errorf("configure %s: %w", mapNameIPv6, err)
	}

	return nil
}

func newFragMap(lifecycle cell.Lifecycle, reg *registry.MapRegistry, metrics *metrics.Registry, daemonConfig *option.DaemonConfig) bpf.MapOut[Map] {
	fragMap := &fragMap{}
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			var err error

			create := func(name string, key bpf.MapKey, value bpf.MapValue) (*bpf.Map, error) {
				m, err := bpf.NewMapFromRegistry(reg, name, key, value)
				if err != nil {
					return nil, fmt.Errorf("create frag map %s from registry: %w", name, err)
				}

				m.WithPressureMetric(metrics).
					WithEvents(daemonConfig.GetEventBufferConfig(name))

				// The map is only created for the datapath, so don't retain an open handle.
				if err := m.Create(); err != nil {
					return nil, fmt.Errorf("create frag map %s: %w", name, err)
				}
				return m, nil
			}

			if daemonConfig.EnableIPv4FragmentsTracking {
				if fragMap.bpfMapV4, err = create(mapNameIPv4, &FragmentKey4{}, &FragmentValue4{}); err != nil {
					return err
				}
			}

			if daemonConfig.EnableIPv6FragmentsTracking {
				if fragMap.bpfMapV6, err = create(mapNameIPv6, &FragmentKey6{}, &FragmentValue6{}); err != nil {
					return err
				}
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(Map(fragMap))
}
