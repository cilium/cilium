// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// Multicast is the name of the flag to enable synthetic multicast.
	Multicast = "multicast-enabled"
)

var Cell = cell.Module(
	"multicastmaps",
	"Multicast Maps provides interfaces to the multicast data-path maps",
	cell.Provide(NewGroupV4Map),
	cell.Config(Config{}),
)

type Config struct {
	MulticastEnabled bool `mapstructure:"multicast-enabled"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(Multicast, cfg.MulticastEnabled, "Enables multicast in Cilium")
}
