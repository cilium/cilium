// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// Interval is the refresh interval for the Double Write Metric Reporter
	Interval = "double-write-metric-reporter-interval"
)

var Cell = cell.Module(
	"double-write-metric-reporter",
	"The Double-Write Metric Reporter compares identities in KVStore and CRD",

	cell.Config(defaultConfig),

	cell.Invoke(registerDoubleWriteMetricReporter),

	metrics.Metric(NewMetrics),
)

type Config struct {
	Interval time.Duration `mapstructure:"double-write-metric-reporter-interval"`
}

var defaultConfig = Config{
	Interval: 1 * time.Minute,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(Interval, def.Interval, "Refresh interval for the Double Write Metric Reporter")
}
