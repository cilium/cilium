// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package http

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type httpHandler struct {
	requests  *prometheus.CounterVec
	responses *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	context   *api.ContextOptions
	useV2     bool
	exemplars bool

	registeredMetrics []*prometheus.MetricVec
}

func (h *httpHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c
	if exemplars, ok := options["exemplars"]; ok && exemplars == "true" {
		h.exemplars = true
	}

	if h.useV2 {
		h.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_requests_total",
			Help:      "Count of HTTP requests",
		}, append(h.context.GetLabelNames(), "method", "protocol", "status", "reporter"))
		h.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "Quantiles of HTTP request duration in seconds",
		}, append(h.context.GetLabelNames(), "method", "reporter"))
		registry.MustRegister(h.requests)
		registry.MustRegister(h.duration)
		h.registeredMetrics = append(h.registeredMetrics, h.requests.MetricVec, h.duration.MetricVec)
	} else {
		h.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_requests_total",
			Help:      "Count of HTTP requests",
		}, append(h.context.GetLabelNames(), "method", "protocol", "reporter"))
		h.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_responses_total",
			Help:      "Count of HTTP responses",
		}, append(h.context.GetLabelNames(), "method", "protocol", "status", "reporter"))
		h.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: api.DefaultPrometheusNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "Quantiles of HTTP request duration in seconds",
		}, append(h.context.GetLabelNames(), "method", "reporter"))
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
	return h.context.Status() + fmt.Sprintf(",exemplars=%t", h.exemplars)
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

	labelValues, err := h.context.GetLabelValuesInvertSourceDestination(flow)
	if err != nil {
		return err
	}

	http := flow.GetL7().GetHttp()
	status := strconv.Itoa(int(http.GetCode()))
	requestsCounter := h.requests.WithLabelValues(append(labelValues, http.GetMethod(), http.GetProtocol(), status, reporter)...)
	requestDurationHistogram := h.duration.WithLabelValues(append(labelValues, http.GetMethod(), reporter)...)

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

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	http := flow.GetL7().GetHttp()
	var requestsCounter, responsesCounter prometheus.Counter
	switch flow.GetL7().GetType() {
	case flowpb.L7FlowType_REQUEST:
		requestsCounter = h.requests.WithLabelValues(append(labelValues, http.GetMethod(), http.GetProtocol(), reporter)...)
		incrementCounter(requestsCounter, traceID)
	case flowpb.L7FlowType_RESPONSE:
		status := strconv.Itoa(int(http.GetCode()))
		responsesCounter = h.responses.WithLabelValues(append(labelValues, http.GetMethod(), http.GetProtocol(), status, reporter)...)
		requestDurationHistogram := h.duration.WithLabelValues(append(labelValues, http.GetMethod(), reporter)...)
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
