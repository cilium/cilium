// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsecrps

import (
	"log/slog"

	"github.com/cilium/hive/cell"
)

func logEnabled(c Config, l *slog.Logger) {
	if c.Enabled() {
		l.Info("Accelerating IPSec throughput with RPS.")
	}
}

var Cell = cell.Module(
	"ipsec-rps-config",
	"Accelerated IPSec with RPS configuration",

	cell.Config(defaultUserFlags),

	cell.Provide(
		newUserCfg,
		newConfig,

		// Provide datapath options.
		Config.datapathConfigProvider,
	),

	cell.Invoke(logEnabled),
)
