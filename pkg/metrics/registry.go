// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/lock"
	metricpkg "github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"

	runtimeMetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var defaultRegistryConfig = RegistryConfig{
	PrometheusServeAddr: "",
}

type RegistryConfig struct {
	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr string
	// This is a list of metrics to be enabled or disabled, format is `+`/`-` + `{metric name}`
	Metrics []string
}

func (rc RegistryConfig) Flags(flags *pflag.FlagSet) {
	flags.String("prometheus-serve-addr", rc.PrometheusServeAddr, "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	flags.StringSlice("metrics", rc.Metrics, "Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo, -metric_bar to disable metric_bar)")
}

// RegistryParams are the parameters needed to construct a Registry
type RegistryParams struct {
	cell.In

	Logger     logrus.FieldLogger
	Shutdowner hive.Shutdowner
	Lifecycle  cell.Lifecycle

	AutoMetrics []metricpkg.WithMetadata `group:"hive-metrics"`
	Config      RegistryConfig

	DaemonConfig *option.DaemonConfig
}

// Registry is a cell around a prometheus registry. This registry starts an HTTP server as part of its lifecycle
// on which all enabled metrics will be available. A reference to this registry can also be used to dynamically
// register or unregister `prometheus.Collector`s.
type Registry struct {
	// inner registry of metrics.
	// Served under the default /metrics endpoint. Each collector is wrapped with
	// [metric.EnabledCollector] to only collect enabled metrics.
	inner *prometheus.Registry

	// collectors holds all registered collectors. Used to periodically sample the
	// metrics.
	collectors collectorSet

	params RegistryParams
}

// Gather exposes metrics gather functionality, used by operator metrics command.
func (reg *Registry) Gather() ([]*dto.MetricFamily, error) {
	return multiRegistry{reg.inner, runtimeMetrics.Registry}.Gather()
}

type multiRegistry []prometheus.Gatherer

func (mg multiRegistry) Gather() ([]*dto.MetricFamily, error) {
	out := []*dto.MetricFamily{}
	var errs error
	for i, reg := range mg {
		ms, err := reg.Gather()
		if err != nil {
			// Note: The Gatherer interface specifies that implementations should
			// still try to return as many metrics even if an error is encountered.
			errs = errors.Join(errs, fmt.Errorf("registry %d: %w", i, err))
			continue
		}
		for _, m := range ms {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b *dto.MetricFamily) int {
		return strings.Compare(a.GetName(), b.GetName())
	})
	return out, errs
}

func (reg *Registry) AddServerRuntimeHooks() {
	if reg.params.Config.PrometheusServeAddr != "" {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		mux := http.NewServeMux()
		rs := multiRegistry{
			reg.inner,
			runtimeMetrics.Registry,
		}
		mux.Handle("/metrics", promhttp.HandlerFor(rs, promhttp.HandlerOpts{}))
		srv := http.Server{
			Addr:    reg.params.Config.PrometheusServeAddr,
			Handler: mux,
		}

		reg.params.Lifecycle.Append(cell.Hook{
			OnStart: func(hc cell.HookContext) error {
				go func() {
					reg.params.Logger.Infof("Serving prometheus metrics on %s", reg.params.Config.PrometheusServeAddr)
					err := srv.ListenAndServe()
					if err != nil && !errors.Is(err, http.ErrServerClosed) {
						reg.params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
					}
				}()
				return nil
			},
			OnStop: func(hc cell.HookContext) error {
				return srv.Shutdown(hc)
			},
		})
	}
}

// NewRegistry constructs a new registry that is not initalized with
// hive/legacy metrics and has registered its runtime hooks yet.
func NewRegistry(params RegistryParams) *Registry {
	reg := &Registry{
		params: params,
		inner:  prometheus.NewPedanticRegistry(),
	}
	return reg
}

func NewAgentRegistry(params RegistryParams) *Registry {
	reg := &Registry{
		params: params,
	}

	reg.Reinitialize()

	// Resolve the global registry variable for as long as we still have global functions
	registryResolver.Resolve(reg)

	reg.AddServerRuntimeHooks()

	return reg
}

// Register registers a collector
func (r *Registry) Register(c prometheus.Collector) error {
	r.collectors.add(c)
	return r.inner.Register(metricpkg.EnabledCollector{C: c})
}

// Unregister unregisters a collector
func (r *Registry) Unregister(c prometheus.Collector) bool {
	r.collectors.remove(c)
	return r.inner.Unregister(c)
}

// goCustomCollectorsRX tracks enabled go runtime metrics.
var goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

// Reinitialize creates a new internal registry and re-registers metrics to it.
// Note: This is only currently used for testing as this will not recreate the prom metrics
// endpoint server.
func (r *Registry) Reinitialize() {
	r.inner = prometheus.NewPedanticRegistry()

	// Default metrics which can't be disabled.
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: Namespace}))
	r.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		)))

	// Don't register status and BPF collectors into the [r.collectors] as it is
	// expensive to sample and currently not terrible useful to keep data on.
	r.inner.MustRegister(metricpkg.EnabledCollector{C: newStatusCollector()})
	r.inner.MustRegister(metricpkg.EnabledCollector{C: newbpfCollector()})

	metrics := make(map[string]metricpkg.WithMetadata)
	for i, autoMetric := range r.params.AutoMetrics {
		metrics[autoMetric.Opts().GetConfigName()] = r.params.AutoMetrics[i]
	}

	// This is a bodge for a very specific feature, inherited from the old `Daemon.additionalMetrics`.
	// We should really find a more generic way to handle such cases.
	metricFlags := r.params.Config.Metrics
	if r.params.DaemonConfig.DNSProxyConcurrencyLimit > 0 {
		metricFlags = append(metricFlags, "+"+Namespace+"_"+SubsystemFQDN+"_semaphore_rejected_total")
	}

	for _, metricFlag := range metricFlags {
		metricFlag = strings.TrimSpace(metricFlag)

		// This is a temporary hack which allows us to get rid of the centralized metric config without refactoring the
		// dynamic map pressure registration/unregistion mechanism.
		// Long term the map pressure metric becomes a smarter component so this is no longer needed.
		if metricFlag[1:] == "-"+Namespace+"_"+SubsystemBPF+"_map_pressure" {
			BPFMapPressure = false
			continue
		}

		metric := metrics[metricFlag[1:]]
		if metric == nil {
			continue
		}

		switch metricFlag[0] {
		case '+':
			metric.SetEnabled(true)
		case '-':
			metric.SetEnabled(false)
		default:
			r.params.Logger.Warning(
				"--metrics flag contains value which does not start with + or -, '%s', ignoring",
				metricFlag,
			)
		}
	}

	for _, m := range metrics {
		if c, ok := m.(prometheus.Collector); ok {
			r.MustRegister(c)
		}
	}
}

// MustRegister adds the collector to the registry, exposing this metric to
// prometheus scrapes.
// It will panic on error.
func (r *Registry) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		r.collectors.add(c)
		r.inner.MustRegister(metricpkg.EnabledCollector{C: c})
	}
}

// RegisterList registers a list of collectors. If registration of one
// collector fails, no collector is registered.
func (r *Registry) RegisterList(list []prometheus.Collector) error {
	registered := []prometheus.Collector{}

	for _, c := range list {
		if err := r.Register(c); err != nil {
			for _, c := range registered {
				r.Unregister(c)
			}
			return err
		}

		registered = append(registered, c)
	}

	return nil
}

// collectorSet holds the prometheus collectors so that we can sample them
// periodically. The collectors are not wrapped with [EnabledCollector] so
// that they're sampled regardless if they're enabled or not.
type collectorSet struct {
	mu         lock.Mutex
	collectors map[prometheus.Collector]struct{}
}

func (cs *collectorSet) collect() <-chan prometheus.Metric {
	ch := make(chan prometheus.Metric, 100)
	go func() {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		defer close(ch)
		for c := range cs.collectors {
			c.Collect(ch)
		}
	}()
	return ch
}

func (cs *collectorSet) add(c prometheus.Collector) {
	cs.mu.Lock()
	if cs.collectors == nil {
		cs.collectors = make(map[prometheus.Collector]struct{})
	}
	cs.collectors[c] = struct{}{}
	cs.mu.Unlock()
}

func (cs *collectorSet) remove(c prometheus.Collector) {
	cs.mu.Lock()
	delete(cs.collectors, c)
	cs.mu.Unlock()
}
