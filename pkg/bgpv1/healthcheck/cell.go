// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

type Config struct {
	BGPReadinessEnabled bool `mapstructure:"bgp-readiness-enabled"`
}

var Cell = cell.Module(
	"bgp-health-check",
	"BGP Health Check",

	cell.Provide(NewBGPStatusGetter),
	cell.Config(defaultConfig),
)

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("bgp-readiness-enabled", def.BGPReadinessEnabled, "Enables BGP readiness probe")

}

var defaultConfig = Config{
	BGPReadinessEnabled: false,
}
