// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"hubble-metrics",
	"Provides metrics for Hubble",

	cell.Config(defaultConfig),
	cell.Invoke(newHubbleMetrics),
)

type Config struct {
	Metrics                       string   `mapstructure:"hubble-metrics"`
	EnableOpenMetrics             bool     `mapstructure:"enable-hubble-open-metrics"`
	MetricsServer                 string   `mapstructure:"hubble-metrics-server"`
	EnableMetricsServerTLS        bool     `mapstructure:"hubble-metrics-server-enable-tls"`
	MetricsServerTLSCertFile      string   `mapstructure:"hubble-metrics-server-tls-cert-file"`
	MetricsServerTLSKeyFile       string   `mapstructure:"hubble-metrics-server-tls-key-file"`
	MetricsServerTLSClientCAFiles []string `mapstructure:"hubble-metrics-server-tls-client-ca-files"`
	DynamicMetricConfigFilePath   string   `mapstructure:"hubble-dynamic-metrics-config-path"`
}

var defaultConfig = Config{
	Metrics:                       "",
	EnableOpenMetrics:             false,
	MetricsServer:                 "",
	EnableMetricsServerTLS:        false,
	MetricsServerTLSCertFile:      "",
	MetricsServerTLSKeyFile:       "",
	MetricsServerTLSClientCAFiles: []string{},
	DynamicMetricConfigFilePath:   "",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("hubble-metrics", def.Metrics, "List of Hubble metrics to enable.")
	flags.Bool("enable-hubble-open-metrics", def.EnableOpenMetrics, "Enable exporting hubble metrics in OpenMetrics format.")
	flags.String("hubble-metrics-server", def.MetricsServer, "Address to serve Hubble metrics on.")
	flags.Bool("hubble-metrics-server-enable-tls", def.EnableMetricsServerTLS, "Run the Hubble metrics server on the given listen address with TLS.")
	flags.String("hubble-metrics-server-tls-cert-file", def.MetricsServerTLSCertFile, "Path to the public key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.String("hubble-metrics-server-tls-key-file", def.MetricsServerTLSKeyFile, "Path to the private key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.StringSlice("hubble-metrics-server-tls-client-ca-files", def.MetricsServerTLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
	flags.String("hubble-dynamic-metrics-config-path", def.DynamicMetricConfigFilePath, "Filepath with dynamic configuration of hubble metrics.")
}

func (cfg Config) Validate() error {
	if cfg.DynamicMetricConfigFilePath != "" && len(cfg.Metrics) > 0 {
		return errors.New("cannot configure both static and dynamic Hubble metrics")
	}
	return nil
}

type params struct {
	cell.In

	Lifecycle cell.Lifecycle

	Config Config
}

func newHubbleMetrics(p params) error {
	if err := p.Config.Validate(); err != nil {
		return fmt.Errorf("hubble metrics server configuration validation failed: %w", err)
	}
	if p.Config.MetricsServer == "" {
		return nil
	}

	s := &metricsServer{}
	p.Lifecycle.Append(s)

	return nil
}
