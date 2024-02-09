// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"github.com/spf13/pflag"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// Interval is the refresh interval for the Double Write Metric Reporter
	Interval = "double-write-metric-reporter-interval"
)

// Cell is a cell that implements a periodic and one-off Cilium endpoints
// garbage collector.
// The GC loops through all the Cilium Endpoints in the cluster and validates
// which one of them should be deleted. Then deleting all that should be
// deleted.
var Cell = cell.Module(
	"double-write-metric-reporter",
	"Double-Write Metric Reporter",

	cell.Config(defaultConfig),

	cell.Invoke(registerDoubleWriteMetricReporter),

	cell.Metric(NewMetrics),
)

// Config contains the configuration for the double-write-metric-reporter
type Config struct {
	Interval time.Duration `mapstructure:"double-write-metric-reporter-interval"`
}

var defaultConfig = Config{
	Interval: 1 * time.Minute,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(Interval, def.Interval, "Refresh interval for the Double Write Metric Reporter")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// Interval is the refresh interval for the Double Write Metric Reporter
	Interval time.Duration
}
