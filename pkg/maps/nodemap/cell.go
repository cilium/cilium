// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/encrypt"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "NodeMap")

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

func newNodeMap(lifecycle cell.Lifecycle, conf Config) (bpf.MapOut[MapV2], error) {
	if conf.NodeMapMax < DefaultMaxEntries {
		return bpf.MapOut[MapV2]{}, fmt.Errorf("creating node map: bpf-node-map-max cannot be less than %d (%d)",
			DefaultMaxEntries, conf.NodeMapMax)
	}
	nodeMap := newMapV2(MapNameV2, MapName, conf)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			if err := nodeMap.init(); err != nil {
				return err
			}

			// do v1 to v2 map migration if necessary
			return nodeMap.migrateV1(MapName, encrypt.MapName)
		},
		OnStop: func(context cell.HookContext) error {
			return nodeMap.close()
		},
	})

	return bpf.NewMapOut(MapV2(nodeMap)), nil
}
