// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module(
	"hubble-metrics",
	"Provides metrics for Hubble",

	cell.Provide(func() *grpc_prometheus.ServerMetrics {
		return grpc_prometheus.NewServerMetrics()
	}),
	cell.ProvidePrivate(func(cfg certloaderConfig) certloader.Config {
		return cfg.Config()
	}),
	cell.Provide(newHubbleMetrics),
	cell.Config(defaultConfig),
)

type Config struct {
	Metrics                     string `mapstructure:"hubble-metrics"`
	EnableOpenMetrics           bool   `mapstructure:"enable-hubble-open-metrics"`
	MetricsServer               string `mapstructure:"hubble-metrics-server"`
	DynamicMetricConfigFilePath string `mapstructure:"hubble-dynamic-metrics-config-path"`
}

var defaultConfig = Config{
	Metrics:                     "",
	EnableOpenMetrics:           false,
	MetricsServer:               "",
	DynamicMetricConfigFilePath: "",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("hubble-metrics", def.Metrics, "List of Hubble metrics to enable.")
	flags.Bool("enable-hubble-open-metrics", def.EnableOpenMetrics, "Enable exporting hubble metrics in OpenMetrics format.")
	flags.String("hubble-metrics-server", def.MetricsServer, "Address to serve Hubble metrics on.")
	flags.String("hubble-dynamic-metrics-config-path", def.DynamicMetricConfigFilePath, "Filepath with dynamic configuration of hubble metrics.")
}

func (cfg Config) Validate() error {
	if cfg.DynamicMetricConfigFilePath != "" && len(cfg.Metrics) > 0 {
		return errors.New("cannot configure both static and dynamic Hubble metrics")
	}
	return nil
}

// certloaderConfig holds the configuration for the metrics server certloader cell.
// The metrics server uses different flag names for the TLS related flags.
// To allow cell re-use, we need a different config type to map the same fields
// to the metrics-server specific TLS flag names.
type certloaderConfig struct {
	TLS              bool     `mapstructure:"hubble-metrics-server-enable-tls"`
	TLSCertFile      string   `mapstructure:"hubble-metrics-server-tls-cert-file"`
	TLSKeyFile       string   `mapstructure:"hubble-metrics-server-tls-key-file"`
	TLSClientCAFiles []string `mapstructure:"hubble-metrics-server-tls-client-ca-files"`
}

var defaultCertloaderConfig = certloaderConfig{
	TLS:              false,
	TLSCertFile:      "",
	TLSKeyFile:       "",
	TLSClientCAFiles: []string{},
}

func (def certloaderConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-metrics-server-enable-tls", def.TLS, "Run the Hubble metrics server on the given listen address with TLS.")
	flags.String("hubble-metrics-server-tls-cert-file", def.TLSCertFile, "Path to the public key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.String("hubble-metrics-server-tls-key-file", def.TLSKeyFile, "Path to the private key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.StringSlice("hubble-metrics-server-tls-client-ca-files", def.TLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}

func (def certloaderConfig) Config() certloader.Config {
	return certloader.Config{
		TLS:              def.TLS,
		TLSCertFile:      def.TLSCertFile,
		TLSKeyFile:       def.TLSKeyFile,
		TLSClientCAFiles: def.TLSClientCAFiles,
	}
}

type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	GRPCServerMetrics *grpc_prometheus.ServerMetrics
	TLSConfigPromise  promise.Promise[*certloader.WatchedServerConfig] `optional:"true"`

	Config Config
}

type out struct {
	cell.Out

	HealthReporter HealthReporter
	// TODO: should we instead provide a concrete metrics.FlowProcessor
	// interface and have the hubble cell register the OnDecodecFlow hooks
	// like we do with the exporter?
	ObserverOptions []observeroption.Option `group:"hubble-observer-options,flatten"`
}

func newHubbleMetrics(p params) (out, error) {
	if err := p.Config.Validate(); err != nil {
		return out{}, fmt.Errorf("hubble metrics server configuration validation failed: %w", err)
	}
	if p.Config.MetricsServer == "" {
		p.Logger.Info("The Hubble metrics server is disabled")
		return out{HealthReporter: &healthReporter{}}, nil
	}

	// metrics server
	metricsServer := newMetricsServer(p)
	p.Lifecycle.Append(metricsServer)

	var observerOptions []observeroption.Option

	// static metrics
	if len(p.Config.Metrics) > 0 {
		p.Logger.Info("Starting Hubble Metrics static flow processor")
		metricConfigs := api.ParseStaticMetricsConfig(strings.Fields(p.Config.Metrics))
		err := metrics.InitMetrics(p.Logger, metrics.Registry, metricConfigs, p.GRPCServerMetrics)
		if err != nil {
			return out{}, fmt.Errorf("failed to setup hubble metrics: %w", err)
		}
		fp := metrics.NewStaticFlowProcessor(p.Logger, metrics.EnabledMetrics)
		observerOptions = append(observerOptions, observeroption.WithOnDecodedFlow(fp))
	}

	// dynamic metrics
	if p.Config.DynamicMetricConfigFilePath != "" {
		p.Logger.Info(
			"Starting Hubble Metrics dynamic flow processor",
			logfields.MetricConfig, p.Config.DynamicMetricConfigFilePath,
		)
		metrics.InitHubbleInternalMetrics(metrics.Registry, p.GRPCServerMetrics)
		fp := metrics.NewDynamicFlowProcessor(metrics.Registry, p.Logger, p.Config.DynamicMetricConfigFilePath)
		observerOptions = append(observerOptions, observeroption.WithOnDecodedFlow(fp))
	}

	return out{
		HealthReporter:  &healthReporter{metricsServer},
		ObserverOptions: observerOptions,
	}, nil
}
