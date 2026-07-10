// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var Cell = cell.Module(
	"hubble-metrics",
	"Provides metrics for Hubble",

	// grpc metrics
	cell.Provide(func() *grpc_prometheus.ServerMetrics {
		return grpc_prometheus.NewServerMetrics()
	}),

	// certloader
	certloaderGroup,

	// hubble metrics
	cell.ProvidePrivate(newValidatedConfig),
	cell.Provide(newMetricsServer),
	cell.Provide(newFlowProcessor),
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

// ValidatedConfig is a config that is known to be valid.
type ValidatedConfig Config

func newValidatedConfig(c Config) (ValidatedConfig, error) {
	if err := c.Validate(); err != nil {
		return ValidatedConfig{}, fmt.Errorf("hubble-metrics configuration validation failed: %w", err)
	}
	return ValidatedConfig(c), nil
}

type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	GRPCServerMetrics *grpc_prometheus.ServerMetrics
	TLSConfigPromise  tlsConfigPromise

	Config ValidatedConfig
}

func newFlowProcessor(p params) (metrics.FlowProcessor, error) {
	if p.Config.MetricsServer == "" {
		return nil, nil
	}

	// ValidatedConfig took care of validating that
	// only one flow processor can be enabled.
	var fp metrics.FlowProcessor
	switch {
	case len(p.Config.Metrics) > 0:
		p.Logger.Info(
			"Starting Hubble Metrics static flow processor",
			logfields.MetricConfig, p.Config.Metrics,
		)
		metricConfigs := api.ParseStaticMetricsConfig(strings.Fields(p.Config.Metrics))
		err := metrics.InitMetrics(p.Logger, metrics.Registry, metricConfigs, p.GRPCServerMetrics)
		if err != nil {
			return nil, fmt.Errorf("failed to setup hubble metrics: %w", err)
		}
		fp = metrics.NewStaticFlowProcessor(p.Logger, metrics.EnabledMetrics)
	case p.Config.DynamicMetricConfigFilePath != "":
		p.Logger.Info(
			"Starting Hubble Metrics dynamic flow processor",
			logfields.MetricConfig, p.Config.DynamicMetricConfigFilePath,
		)
		metrics.InitHubbleInternalMetrics(metrics.Registry, p.GRPCServerMetrics)
		fp = metrics.NewDynamicFlowProcessor(metrics.Registry, p.Logger, p.Config.DynamicMetricConfigFilePath)
	}

	return fp, nil
}
