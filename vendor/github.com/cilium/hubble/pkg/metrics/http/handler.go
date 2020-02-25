// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http

import (
	"strconv"
	"time"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"

	"github.com/prometheus/client_golang/prometheus"
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

func (h *httpHandler) ProcessFlow(flow v1.Flow) {
	l7 := flow.GetL7()
	if l7 == nil {
		return
	}
	http := l7.GetHttp()
	if http == nil {
		return
	}
	labelValues := h.context.GetLabelValues(flow)
	if l7.Type == pb.L7FlowType_REQUEST {
		h.requests.WithLabelValues(append(labelValues, http.Method, http.Protocol)...).Inc()
	} else if l7.Type == pb.L7FlowType_RESPONSE {
		status := strconv.Itoa(int(http.Code))
		h.responses.WithLabelValues(append(labelValues, status, http.Method)...).Inc()
		h.duration.WithLabelValues(append(labelValues, http.Method)...).Observe(float64(l7.LatencyNs) / float64(time.Second))
	}
}
