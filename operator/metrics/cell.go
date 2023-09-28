// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
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

	cell.Config(defaultConfig),
	cell.Invoke(registerMetricsManager),
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
// Metrics cell needs to know if GatewayAPI is enabled in order to use
// the same Registry as controller-runtime and avoid to expose
// multiple metrics endpoints or servers.
type SharedConfig struct {
	// EnableMetrics is set to true if operator metrics are enabled
	EnableMetrics bool

	// EnableGatewayAPI enables support of Gateway API
	EnableGatewayAPI bool
}
