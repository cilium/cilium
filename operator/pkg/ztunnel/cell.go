// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var DefaultConfig = Config{
	EnableZTunnel: false,
}

type Config struct {
	EnableZTunnel bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
}

// Cell provides ztunnel configuration.
var Cell = cell.Module(
	"ztunnel",
	"ZTunnel Configuration",

	cell.Config(DefaultConfig),
)
