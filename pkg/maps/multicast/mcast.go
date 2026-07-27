// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	// Multicast is the name of the flag to enable synthetic multicast.
	Multicast = "multicast-enabled"
)

var Cell = cell.Module(
	"multicastmaps",
	"Multicast Maps provides interfaces to the multicast data-path maps",
	cell.Provide(NewGroupV4Map),
	cell.Config(defaultConfig),
)

type Config struct {
	MulticastEnabled bool `mapstructure:"multicast-enabled"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(Multicast, cfg.MulticastEnabled, "Enables multicast in Cilium")
}

var defaultConfig = Config{
	MulticastEnabled: false,
}
