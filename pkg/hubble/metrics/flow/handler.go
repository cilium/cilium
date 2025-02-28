// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package flow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type flowHandler struct {
	flows     *prometheus.CounterVec
	context   *api.ContextOptions
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *flowHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	labels := []string{"protocol", "type", "subtype", "verdict"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.flows = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "flows_processed_total",
		Help:      "Total number of flows processed",
	}, labels)

	registry.MustRegister(h.flows)
	return nil
}

func (h *flowHandler) Status() string {
	return h.context.Status()
}

func (h *flowHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *flowHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.flows.MetricVec}
}

func (h *flowHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}
	var typeName, subType string
	eventType := flow.GetEventType().GetType()
	switch eventType {
	case monitorAPI.MessageTypeAccessLog:
		typeName = "L7"
		if l7 := flow.GetL7(); l7 != nil {
			switch {
			case l7.GetDns() != nil:
				subType = "DNS"
			case l7.GetHttp() != nil:
				subType = "HTTP"
			case l7.GetKafka() != nil:
				subType = "Kafka"
			}
		}
	case monitorAPI.MessageTypeDrop:
		typeName = "Drop"
	case monitorAPI.MessageTypeCapture:
		typeName = "Capture"
	case monitorAPI.MessageTypeTrace:
		typeName = "Trace"
		subType = monitorAPI.TraceObservationPoints[uint8(flow.GetEventType().SubType)]
	case monitorAPI.MessageTypePolicyVerdict:
		typeName = "PolicyVerdict"
	default:
		typeName = "Unknown"
		subType = fmt.Sprintf("%d", eventType)
	}

	labels := []string{v1.FlowProtocol(flow), typeName, subType, flow.GetVerdict().String()}
	labels = append(labels, labelValues...)

	h.flows.WithLabelValues(labels...).Inc()
	return nil
}

func (h *flowHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.flows) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "flows_processed_total"))
	}
	return errs
}

func (h *flowHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *flowHandler) SetFilters(cfg *api.MetricConfig) error {
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
