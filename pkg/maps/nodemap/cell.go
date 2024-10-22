// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell provides the nodemap.MapV2 which contains information about node IDs, SPIs, and their IP addresses.
var Cell = cell.Module(
	"node-map",
	"eBPF map which contains information about node IDs and their IP addresses",

	cell.Provide(newNodeMap),
	cell.Config(defaultConfig),
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

func newNodeMap(lifecycle cell.Lifecycle, conf Config, logger *slog.Logger) (bpf.MapOut[MapV2], error) {
	if conf.NodeMapMax < DefaultMaxEntries {
		return bpf.MapOut[MapV2]{}, fmt.Errorf("creating node map: bpf-node-map-max cannot be less than %d (%d)",
			DefaultMaxEntries, conf.NodeMapMax)
	}
	nodeMap := newMapV2(logger, MapNameV2, conf)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			nodeMap.migrateV1("cilium_node_map")

			return nodeMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return nodeMap.close()
		},
	})

	return bpf.NewMapOut(MapV2(nodeMap)), nil
}
