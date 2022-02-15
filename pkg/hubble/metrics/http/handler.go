// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package http

import (
	"context"
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
}

func (h *httpHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c
	h.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "http_requests_total",
		Help:      "Count of HTTP requests",
	}, append(h.context.GetLabelNames(), "method", "protocol"))
	h.responses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "http_responses_total",
		Help:      "Count of HTTP responses",
	}, append(h.context.GetLabelNames(), "status", "method"))
	h.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "http_request_duration_seconds",
		Help:      "Quantiles of HTTP request duration in seconds",
	}, append(h.context.GetLabelNames(), "method"))
	registry.MustRegister(h.requests)
	registry.MustRegister(h.responses)
	registry.MustRegister(h.duration)
	return nil
}

func (h *httpHandler) Status() string {
	if h.context == nil {
		return ""
	}
	return h.context.Status()
}

func (h *httpHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) {
	l7 := flow.GetL7()
	if l7 == nil {
		return
	}
	http := l7.GetHttp()
	if http == nil {
		return
	}
	labelValues := h.context.GetLabelValues(flow)
	if l7.Type == flowpb.L7FlowType_REQUEST {
		h.requests.WithLabelValues(append(labelValues, http.Method, http.Protocol)...).Inc()
	} else if l7.Type == flowpb.L7FlowType_RESPONSE {
		status := strconv.Itoa(int(http.Code))
		h.responses.WithLabelValues(append(labelValues, status, http.Method)...).Inc()
		h.duration.WithLabelValues(append(labelValues, http.Method)...).Observe(float64(l7.LatencyNs) / float64(time.Second))
	}
}
