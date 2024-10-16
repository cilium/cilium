// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package cpumap

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"cpu-map",
	"eBPF map that allows for utilizing the bpf_redirect_map helper in XDP programs",

	cell.Config(defaultUserConfig),
	cell.Provide(
		newConfig,
		newCPUMap,
	),
)

// TestConfigCell is a subset of the full cpumap cell that only contains
// the functionality to output a configuration. This can be consumed by unit
// tests which may depend on the state of the cpumap Config.
var TestConfigCell = cell.Module(
	"test-cpu-map-config",
	"Provide CPUMap config to unit tests",

	cell.Config(defaultUserConfig),
	cell.Provide(newConfig),
)
