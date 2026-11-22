// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/hubble/metrics/pathtemplate"
	"github.com/cilium/cilium/pkg/time"
)

type httpHandler struct {
	requests  *prometheus.CounterVec
	responses *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	context   *api.ContextOptions
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
	useV2     bool
	exemplars bool

	// paths is nil unless pathContext is set.
	paths      *pathtemplate.Matcher
	missValue  string
	dropOnMiss bool

	registeredMetrics []*prometheus.MetricVec
}

func (h *httpHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c

	paths, err := options.CompilePathContext()
	if err != nil {
		return err
	}
	if paths != nil {
		h.paths = paths
		h.missValue = options.PathContext.OnMiss.Value
		h.dropOnMiss = options.PathContext.DropOnMiss()
	}

	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	for _, opt := range options.ContextOptionConfigs {
		if strings.ToLower(opt.Name) == "exemplars" {
			if len(opt.Values) >= 1 && opt.Values[0] == "true" {
				h.exemplars = true
			}
			break
		}
	}

	if h.useV2 {
		h.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_requests_total",
			Help:      "Count of HTTP requests",
		}, h.labelNames("method", "protocol", "status", "reporter"))
		h.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "Quantiles of HTTP request duration in seconds",
		}, h.labelNames("method", "reporter"))
		registry.MustRegister(h.requests)
		registry.MustRegister(h.duration)
		h.registeredMetrics = append(h.registeredMetrics, h.requests.MetricVec, h.duration.MetricVec)
	} else {
		h.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_requests_total",
			Help:      "Count of HTTP requests",
		}, h.labelNames("method", "protocol", "reporter"))
		h.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_responses_total",
			Help:      "Count of HTTP responses",
		}, h.labelNames("method", "protocol", "status", "reporter"))
		h.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "Quantiles of HTTP request duration in seconds",
		}, h.labelNames("method", "reporter"))
		registry.MustRegister(h.requests)
		registry.MustRegister(h.responses)
		registry.MustRegister(h.duration)
		h.registeredMetrics = append(h.registeredMetrics, h.requests.MetricVec, h.responses.MetricVec, h.duration.MetricVec)
	}
	return nil
}

func (h *httpHandler) Status() string {
	if h.context == nil {
		return ""
	}
	status := h.context.Status() + fmt.Sprintf(",exemplars=%t", h.exemplars)
	if h.paths != nil {
		onMiss := api.OnMissEmit
		if h.dropOnMiss {
			onMiss = api.OnMissDropSample
		}
		status += fmt.Sprintf(",pathTemplates=%d,onMiss=%s", h.paths.Len(), onMiss)
	}
	return status
}

// labelNames puts "path" last: the fixed labels differ per metric, so last is
// the only position common to all of them.
func (h *httpHandler) labelNames(fixed ...string) []string {
	return h.labelValues(h.context.GetLabelNames(), "path", fixed...)
}

// labelValues follows labelNames order. It copies, so context can be reused.
func (h *httpHandler) labelValues(context []string, path string, fixed ...string) []string {
	var p []string
	if h.paths != nil {
		p = []string{path}
	}
	return slices.Concat(context, fixed, p)
}

// matchPath returns the "path" label value, and false if the sample is dropped.
// It matches EscapedPath because Path is percent-decoded, which turns %2F into
// a segment boundary. An unparseable URL is a miss rather than an error, which
// would drop the flow from every HTTP metric.
func (h *httpHandler) matchPath(http *flowpb.HTTP) (string, bool) {
	if h.paths == nil {
		return "", true
	}
	if u, err := url.Parse(http.GetUrl()); err == nil {
		if template, ok := h.paths.Match(u.EscapedPath()); ok {
			return template, true
		}
	}
	return h.missValue, !h.dropOnMiss
}

func (h *httpHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *httpHandler) ListMetricVec() []*prometheus.MetricVec {
	return h.registeredMetrics
}

func (h *httpHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if h.useV2 {
		return h.processMetricsV2(flow)
	} else {
		return h.processMetricsV1(flow)
	}
}

func (h *httpHandler) isHTTP(flow *flowpb.Flow) bool {
	return flow.GetL7().GetHttp() != nil
}

func (h *httpHandler) reporter(flow *flowpb.Flow) string {
	reporter := "unknown"
	switch flow.GetTrafficDirection() {
	case flowpb.TrafficDirection_EGRESS:
		reporter = "client"
	case flowpb.TrafficDirection_INGRESS:
		reporter = "server"
	}
	return reporter
}

func (h *httpHandler) traceID(flow *flowpb.Flow) string {
	if h.exemplars {
		return flow.GetTraceContext().GetParent().GetTraceId()
	}
	return ""
}

func (h *httpHandler) processMetricsV2(flow *flowpb.Flow) error {
	if !h.isHTTP(flow) || flow.GetL7().GetType() != flowpb.L7FlowType_RESPONSE {
		return nil
	}
	reporter := h.reporter(flow)
	traceID := h.traceID(flow)

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValuesInvertSourceDestination(flow)
	if err != nil {
		return err
	}

	http := flow.GetL7().GetHttp()
	path, keep := h.matchPath(http)
	if !keep {
		return nil
	}
	status := strconv.Itoa(int(http.GetCode()))
	requestsCounter := h.requests.WithLabelValues(h.labelValues(labelValues, path, http.GetMethod(), http.GetProtocol(), status, reporter)...)
	requestDurationHistogram := h.duration.WithLabelValues(h.labelValues(labelValues, path, http.GetMethod(), reporter)...)

	incrementCounter(requestsCounter, traceID)
	observerObserve(requestDurationHistogram, float64(flow.GetL7().GetLatencyNs())/float64(time.Second), traceID)

	return nil
}

func (h *httpHandler) processMetricsV1(flow *flowpb.Flow) error {
	if !h.isHTTP(flow) {
		return nil
	}
	flowType := flow.GetL7().GetType()
	if flowType != flowpb.L7FlowType_REQUEST && flowType != flowpb.L7FlowType_RESPONSE {
		return nil
	}
	reporter := h.reporter(flow)
	traceID := h.traceID(flow)

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	http := flow.GetL7().GetHttp()
	path, keep := h.matchPath(http)
	if !keep {
		return nil
	}
	var requestsCounter, responsesCounter prometheus.Counter
	switch flow.GetL7().GetType() {
	case flowpb.L7FlowType_REQUEST:
		requestsCounter = h.requests.WithLabelValues(h.labelValues(labelValues, path, http.GetMethod(), http.GetProtocol(), reporter)...)
		incrementCounter(requestsCounter, traceID)
	case flowpb.L7FlowType_RESPONSE:
		status := strconv.Itoa(int(http.GetCode()))
		responsesCounter = h.responses.WithLabelValues(h.labelValues(labelValues, path, http.GetMethod(), http.GetProtocol(), status, reporter)...)
		requestDurationHistogram := h.duration.WithLabelValues(h.labelValues(labelValues, path, http.GetMethod(), reporter)...)
		incrementCounter(responsesCounter, traceID)
		observerObserve(requestDurationHistogram, float64(flow.GetL7().GetLatencyNs())/float64(time.Second), traceID)
	}
	return nil
}

func incrementCounter(c prometheus.Counter, traceID string) {
	if adder, ok := c.(prometheus.ExemplarAdder); ok && traceID != "" {
		adder.AddWithExemplar(1, prometheus.Labels{"traceID": traceID})
	} else {
		c.Inc()
	}
}

func observerObserve(o prometheus.Observer, value float64, traceID string) {
	if adder, ok := o.(prometheus.ExemplarObserver); ok && traceID != "" {
		adder.ObserveWithExemplar(value, prometheus.Labels{"traceID": traceID})
	} else {
		o.Observe(value)
	}
}

func (h *httpHandler) Deinit(registry *prometheus.Registry) error {
	var errs error

	if !registry.Unregister(h.requests) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "http_requests_total"))
	}
	if !h.useV2 {
		if !registry.Unregister(h.responses) {
			errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "http_responses_total"))
		}
	}
	if !registry.Unregister(h.duration) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "http_request_duration_seconds"))
	}
	return errs
}

func (h *httpHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *httpHandler) SetFilters(cfg *api.MetricConfig) error {
	var err error
	h.AllowList, err = filters.BuildFilterList(context.Background(), cfg.IncludeFilters, filters.DefaultFilters(slog.Default()))
	if err != nil {
		return err
	}
	h.DenyList, err = filters.BuildFilterList(context.Background(), cfg.ExcludeFilters, filters.DefaultFilters(slog.Default()))
	if err != nil {
		return err
	}
	return nil
}
