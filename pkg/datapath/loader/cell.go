// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/loader/types"
)

var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Config(defaultConfig),
	cell.Provide(NewLoader),
	cell.Provide(NewCompilationLock),
)

// loaderConfig is the user configuration of the loader.
type loaderConfig struct {
	DisableTimerMigration bool
}

var defaultConfig = loaderConfig{
	DisableTimerMigration: true,
}

func (def loaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("disable-timer-migration", def.DisableTimerMigration,
		"Set kernel.timer_migration to 0 on datapath initialization. "+
			"If false, Cilium leaves the sysctl unchanged, for example for nodes with isolated CPUs")
}

// NewLoader returns a new loader.
func NewLoader(p Params) types.Loader {
	return newLoader(p)
}
