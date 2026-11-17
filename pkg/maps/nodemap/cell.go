// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
)

// Cell provides the nodemap.MapV2 which contains information about node IDs, SPIs, and their IP addresses.
var Cell = cell.Module(
	"node-map",
	"eBPF map which contains information about node IDs and their IP addresses",

	cell.Provide(newNodeMap),
	cell.Config(defaultConfig),
	cell.Invoke(configureNodeMap),
)

type Config struct {
	NodeMapMax uint32 `mapstructure:"bpf-node-map-max"`
}

func (c Config) Flags(fs *pflag.FlagSet) {
	fs.Uint32("bpf-node-map-max", defaultConfig.NodeMapMax,
		"Sets size of node bpf map which will be the max number of unique Node IPs in the cluster")
}

var defaultConfig = Config{
	NodeMapMax: DefaultMaxEntries,
}

func newNodeMap(lifecycle cell.Lifecycle, mapRegistry *mapregistry.MapRegistry,
	conf Config) (bpf.MapOut[MapV2], error) {
	if conf.NodeMapMax < DefaultMaxEntries {
		return bpf.MapOut[MapV2]{}, fmt.Errorf("creating node map: bpf-node-map-max cannot be less than %d (%d)",
			DefaultMaxEntries, conf.NodeMapMax)
	}
	nodeMap := &nodeMapV2{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			var err error
			if nodeMap.bpfMap, err = bpf.NewMapFromRegistry(mapRegistry, MapNameV2, &NodeKey{},
				&NodeValueV2{}); err != nil {
				return fmt.Errorf("pull %s map from registry: %w", MapNameV2, err)
			}

			if err := nodeMap.bpfMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("open/create %s map: %w", MapNameV2, err)
			}
			return nil
		},
		OnStop: func(context cell.HookContext) error {
			if err := nodeMap.bpfMap.Close(); err != nil {
				return fmt.Errorf("close %s map: %w", MapNameV2, err)
			}
			return nil
		},
	})

	return bpf.NewMapOut(MapV2(nodeMap)), nil
}

func configureNodeMap(reg *mapregistry.MapRegistry, conf Config) error {
	flags := bpf.GetMapMemoryFlags(ebpf.Hash) | unix.BPF_F_RDONLY_PROG
	maxEntries := conf.NodeMapMax
	if err := reg.Modify(MapNameV2, func(patch *mapregistry.MapSpecPatch) {
		patch.Flags = flags
		patch.MaxEntries = maxEntries
	}); err != nil {
		return fmt.Errorf("error setting %s map flags and max entries: %w", MapNameV2, err)
	}
	return nil
}
