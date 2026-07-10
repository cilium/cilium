// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package drop

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
)

type dropHandler struct {
	drops     *prometheus.CounterVec
	context   *api.ContextOptions
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *dropHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	contextLabels := h.context.GetLabelNames()
	labels := append(contextLabels, "reason", "protocol")

	h.drops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "drop_total",
		Help:      "Number of drops",
	}, labels)

	registry.MustRegister(h.drops)
	return nil
}

func (h *dropHandler) Status() string {
	return h.context.Status()
}

func (h *dropHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *dropHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.drops.MetricVec}
}

func (h *dropHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return nil
	}

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	contextLabels, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	labels := append(contextLabels, flow.GetDropReasonDesc().String(), v1.FlowProtocol(flow))

	h.drops.WithLabelValues(labels...).Inc()
	return nil
}

func (h *dropHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.drops) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "drop_total"))
	}
	return errs
}

func (h *dropHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *dropHandler) SetFilters(cfg *api.MetricConfig) error {
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
