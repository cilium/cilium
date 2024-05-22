// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamic

import (
	"github.com/cilium/cilium/pkg/labelsfilter/dynamic/signals"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"dlf-policy-watcher",
	"Watches network policies events to update dynamic label filter",

	cell.ProvidePrivate(signals.NewSignal),
	cell.Invoke(registerController),

	cell.Config(config{
		EnableDynamicLabelFilter: false,
	}),
)

type config struct {
	EnableDynamicLabelFilter bool
}

func (defaults config) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableDynamicLabelFilter, defaults.EnableDynamicLabelFilter, "Enables support for dynamically limiting the labels used for CIDs")
}
