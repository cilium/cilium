// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// SDPPrometheusServeAddr is the flag name for the standalone DNS proxy
	// prometheus metrics serve address.
	SDPPrometheusServeAddr = "sdp-prometheus-serve-addr"
)

// Cell provides the modular metrics registry and metric HTTP server
// for the standalone DNS proxy.
var Cell = cell.Module(
	"sdp-metrics",
	"Standalone DNS Proxy Metrics",

	cell.Config(defaultConfig),
	cell.Provide(func(conf Config) metrics.RegistryConfig {
		return metrics.RegistryConfig{
			PrometheusServeAddr: conf.SDPPrometheusServeAddr,
		}
	}),
	metrics.NewCell("sdp"),
	metrics.Metric(NewMetrics),
	cell.Invoke(initializeMetrics),
)

type Config struct {
	SDPPrometheusServeAddr string
}

var defaultConfig = Config{
	SDPPrometheusServeAddr: ":9961",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(SDPPrometheusServeAddr, def.SDPPrometheusServeAddr, "Address to serve Prometheus metrics for the standalone DNS proxy")
}
