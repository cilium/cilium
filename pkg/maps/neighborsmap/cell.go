// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighborsmap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/kpr"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the neighborsmap.Map that stores IP to mac address
// mappings for NodePort clients. It is primarily managed from the
// datapath; Cilium side is used to create the map only.
var Cell = cell.Module(
	"neighbors-map",
	"Initializes neighbors bpf map",

	// Provided to init at startup (The Loader depends on all maps via bpf.Mapout)
	cell.Provide(newNeighborsMap),
	cell.Invoke(configure),
)

func newNeighborsMap(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, kprConfig kpr.KPRConfig, reg *mapregistry.MapRegistry) bpf.MapOut[Map] {
	if !kprConfig.KubeProxyReplacement {
		return bpf.NewMapOut(Map(nil))
	}

	neighborsMap := &neighborsMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return neighborsMap.init(reg, daemonConfig.IPv4Enabled(), daemonConfig.IPv6Enabled())
		},
		OnStop: func(context cell.HookContext) error {
			// no need to close because the maps are only created for datapath (Create)
			return nil
		},
	})

	return bpf.NewMapOut(Map(neighborsMap))
}

func configure(reg *mapregistry.MapRegistry, daemonConfig *option.DaemonConfig) error {
	var flags uint32
	if daemonConfig.BPFDistributedLRU {
		flags = unix.BPF_F_NO_COMMON_LRU
	}

	for _, name := range []string{map4Name, map6Name} {
		if err := reg.Modify(name, func(m *mapregistry.MapSpecPatch) {
			m.MaxEntries = uint32(daemonConfig.NeighMapEntriesGlobal)
			// Registry patches also replace the flags from the compiled map.
			m.Flags = flags
		}); err != nil {
			return fmt.Errorf("configure neighbor map %s: %w", name, err)
		}
	}
	return nil
}
