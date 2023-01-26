// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"net/http"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics/metric"
	pkgmetric "github.com/cilium/cilium/pkg/metrics/metric"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/spf13/pflag"
)

var defaultRegistryConfig = RegistryConfig{
	PrometheusServeAddr: ":9962",
}

type RegistryConfig struct {
	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr string
	//
	Metrics []string
}

func (rc RegistryConfig) Flags(flags *pflag.FlagSet) {
	flags.String("prometheus-serve-addr", rc.PrometheusServeAddr, "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	flags.StringSlice("metrics", rc.Metrics, "Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo , -metric_bar to disable metric_bar)")
}

type Registry struct {
	config     RegistryConfig
	shutdowner hive.Shutdowner

	registry *prometheus.Registry
	server   *http.Server
}

type RegistryParams struct {
	cell.In

	Config     RegistryConfig
	Lifecycle  hive.Lifecycle
	Shutdowner hive.Shutdowner
	Metrics    []pkgmetric.WithMetadata `group:"hive-metrics"`
}

func NewRegistry(params RegistryParams) (*Registry, error) {
	reg := &Registry{
		config:     params.Config,
		shutdowner: params.Shutdowner,
		registry:   prometheus.NewPedanticRegistry(),
	}

	metrics := make(map[string]pkgmetric.WithMetadata)
	for _, metric := range params.Metrics {
		if collector, ok := metric.(prometheus.Collector); ok {
			reg.registry.Register(collector)
		}
		metrics[metric.Opts().FullyQualifiedName()] = metric
	}

	// TODO daemon additional metrics

	for _, metricFlag := range params.Config.Metrics {
		metric := metrics[metricFlag[1:]]
		if metric == nil {
			continue
		}

		switch metricFlag[0] {
		case '+':
			metric.SetEnabled(true)
		case '-':
			metric.SetEnabled(false)
		}
	}

	// Default metrics TODO: convert to metric cells
	reg.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: Namespace}))
	reg.registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		)))
	reg.registry.MustRegister(newStatusCollector())
	reg.registry.MustRegister(newbpfCollector())

	params.Lifecycle.Append(reg)

	return reg, nil
}

func (r *Registry) Start(_ hive.HookContext) error {
	// No point in doing anything if we will not serve the metrics
	if r.config.PrometheusServeAddr == "" {
		return nil
	}

	go func() {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{}))
		r.server = &http.Server{
			Addr:    r.config.PrometheusServeAddr,
			Handler: mux,
		}

		err := r.server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			r.shutdowner.Shutdown(hive.ShutdownWithError(err))
		}
	}()

	return nil
}

func (r *Registry) Stop(stopCtx hive.HookContext) error {
	return r.server.Shutdown(stopCtx)
}

// DumpMetrics gets the current Cilium metrics and dumps all into a
// models.Metrics structure.If metrics cannot be retrieved, returns an error
func (r *Registry) DumpMetrics() ([]*models.Metric, error) {
	result := []*models.Metric{}
	currentMetrics, err := r.registry.Gather()
	if err != nil {
		return result, err
	}

	for _, val := range currentMetrics {

		metricName := val.GetName()
		metricType := val.GetType()

		for _, metricLabel := range val.Metric {
			labels := map[string]string{}
			for _, label := range metricLabel.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}

			var value float64
			switch metricType {
			case dto.MetricType_COUNTER:
				value = metricLabel.Counter.GetValue()
			case dto.MetricType_GAUGE:
				value = metricLabel.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				value = metricLabel.GetUntyped().GetValue()
			case dto.MetricType_SUMMARY:
				value = metricLabel.GetSummary().GetSampleSum()
			case dto.MetricType_HISTOGRAM:
				value = metricLabel.GetHistogram().GetSampleSum()
			default:
				continue
			}

			metric := &models.Metric{
				Name:   metricName,
				Labels: labels,
				Value:  value,
			}
			result = append(result, metric)
		}
	}
	return result, nil
}

// Register allows for runtime registration
// Deprecated: do not use
func (reg *Registry) Register(metric metric.WithMetadata) error {
	if collector, ok := metric.(prometheus.Collector); ok {
		reg.registry.Register(collector)
	}

	return nil
}
