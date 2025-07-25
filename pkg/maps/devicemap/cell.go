// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

// Cell provides the devicemap.Map which contains information about device ifindexes and their macs.
var Cell = cell.Module(
	"device-map",
	"eBPF map which contains information about device ifindexes and their macs",

	cell.Provide(newDeviceMap),
)

func newDeviceMap(lifecycle cell.Lifecycle, logger *slog.Logger) (bpf.MapOut[Map], defines.NodeOut) {
	deviceMap := newMap(logger)

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return deviceMap.init()
		},
		OnStop: func(context cell.HookContext) error {
			return deviceMap.close()
		},
	})

	nodeOut := defines.NodeOut{
		NodeDefines: defines.Map{
			"DEVICE_MAP_SIZE": fmt.Sprint(MaxEntries),
		},
	}

	return bpf.NewMapOut(Map(deviceMap)), nodeOut
}
