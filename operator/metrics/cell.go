// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// OperatorPrometheusServeAddr IP:Port on which to serve prometheus metrics
	// (pass ":<port>" to bind on all interfaces).
	OperatorPrometheusServeAddr = "operator-prometheus-serve-addr"
)

// Cell provides the modular metrics registry, metric HTTP server and
// legacy metrics cell for the operator.
var Cell = cell.Module(
	"operator-metrics",
	"Operator Metrics",

	certloaderGroup,
	cell.Config(defaultConfig),
	// RegistryConfig implements the config type for the agent Cell,
	// however the operator has a different flag name for this the
	// server address flag so we configure this ourselves.
	cell.Provide(func(conf Config) metrics.RegistryConfig {
		return metrics.RegistryConfig{
			PrometheusServeAddr: conf.OperatorPrometheusServeAddr,
		}
	}),
	// Metrics cell provides a bare-bones registry that has not been initialized yet.
	metrics.NewCell("operator"),
	cell.Invoke(initializeMetrics),
)

// Config contains the configuration for the operator-metrics cell.
type Config struct {
	OperatorPrometheusServeAddr string
}

var defaultConfig = Config{
	// default server address for operator metrics
	OperatorPrometheusServeAddr: ":9963",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(OperatorPrometheusServeAddr, def.OperatorPrometheusServeAddr, "Address to serve Prometheus metrics")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
type SharedConfig struct {
	// EnableMetrics is set to true if operator metrics are enabled
	EnableMetrics bool
}
