// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driftchecker

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

// Cell will monitor the configuration drift from DynamicConfig table.
// It allows agent to monitor the configuration drift and publish
// `drift_checker_config_delta` metric reporting the diff delta.
var Cell = cell.Module(
	"config-drift-checker",
	"Monitor configuration cilium configuration drift from DynamicConfig table",
	cell.Invoke(Register),
	metrics.Metric(MetricsProvider),
	cell.Config(defaultConfig),
)

var defaultConfig = config{
	EnableDriftChecker:      false,
	IgnoreFlagsDriftChecker: []string{},
}

type config struct {
	EnableDriftChecker      bool
	IgnoreFlagsDriftChecker []string
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-drift-checker", c.EnableDriftChecker, "Enables support for config drift checker")
	flags.StringSlice("ignore-flags-drift-checker", c.IgnoreFlagsDriftChecker, "Ignores specified flags during drift checking")
}
