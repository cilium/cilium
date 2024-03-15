// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell provides the nodemap.Map which contains information about node IDs and their IP addresses.
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

func newNodeMap(lifecycle cell.Lifecycle, conf Config) (bpf.MapOut[Map], error) {
	if conf.NodeMapMax < DefaultMaxEntries {
		return bpf.MapOut[Map]{}, fmt.Errorf("creating node map: bpf-node-map-max cannot be less than %d (%d)",
			DefaultMaxEntries, conf.NodeMapMax)
	}
	nodeMap := newMap(MapName, conf)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return nodeMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return nodeMap.close()
		},
	})

	return bpf.NewMapOut(Map(nodeMap)), nil
}
