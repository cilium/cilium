// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package kafka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/time"
)

type kafkaHandler struct {
	requests  *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	context   *api.ContextOptions
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *kafkaHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	h.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "kafka_requests_total",
		Help:      "Count of Kafka requests",
	}, append(h.context.GetLabelNames(), "topic", "api_key", "error_code", "reporter"))
	h.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "kafka_request_duration_seconds",
		Help:      "Quantiles of HTTP request duration in seconds",
	}, append(h.context.GetLabelNames(), "topic", "api_key", "reporter"))
	registry.MustRegister(h.requests)
	registry.MustRegister(h.duration)
	return nil
}

func (h *kafkaHandler) Status() string {
	if h.context == nil {
		return ""
	}
	return h.context.Status()
}

func (h *kafkaHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *kafkaHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.requests.MetricVec, h.duration.MetricVec}
}

func (h *kafkaHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	l7 := flow.GetL7()
	if l7 == nil {
		return nil
	}
	kafka := l7.GetKafka()
	if kafka == nil {
		return nil
	}

	if l7.Type != flowpb.L7FlowType_REQUEST {
		return nil
	}

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	reporter := "unknown"
	switch flow.GetTrafficDirection() {
	case flowpb.TrafficDirection_EGRESS:
		reporter = "client"
	case flowpb.TrafficDirection_INGRESS:
		reporter = "server"
	}

	h.requests.WithLabelValues(append(labelValues, kafka.Topic, kafka.ApiKey, strconv.Itoa(int(kafka.ErrorCode)), reporter)...).Inc()
	h.duration.WithLabelValues(append(labelValues, kafka.Topic, kafka.ApiKey, reporter)...).Observe(float64(l7.LatencyNs) / float64(time.Second))
	return nil
}

func (h *kafkaHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.requests) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "kafka_requests_total"))
	}
	if !registry.Unregister(h.duration) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "kafka_request_duration_seconds"))
	}
	return errs
}

func (h *kafkaHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *kafkaHandler) SetFilters(cfg *api.MetricConfig) error {
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
