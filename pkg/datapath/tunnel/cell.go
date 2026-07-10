// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/option"
)

// Cell is a cell that provides the parameters for the Cilium tunnel,
// based on user configuration and requests from external modules.
var Cell = cell.Module(
	"datapath-tunnel-config",
	"Tunneling configurations",

	cell.Config(defaultConfig),

	cell.Provide(
		newConfig,

		// Provide the datapath options.
		Config.datapathConfigProvider,

		// Enable tunnel configuration when it is the primary routing mode.
		func(dcfg *option.DaemonConfig) EnablerOut {
			return NewEnabler(dcfg.TunnelingEnabled())
		},
	),
)
