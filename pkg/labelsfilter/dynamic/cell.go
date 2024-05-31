// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamic

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"dynamic-labels-filter",
	"Watches network policies events to update dynamic labels filter",

	cell.Invoke(registerController),

	cell.Config(config{
		EnableDynamicLabelsFilter: false,
	}),
)

type config struct {
	EnableDynamicLabelsFilter bool
}

func (defaults config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-dynamic-labels-filter", defaults.EnableDynamicLabelsFilter, "Enables support for dynamically limiting the labels used for CIDs")
}
