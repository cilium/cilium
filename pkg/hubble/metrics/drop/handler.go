// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package drop

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type dropHandler struct {
	drops     *prometheus.CounterVec
	context   *api.ContextOptions
	cfg       *api.MetricConfig
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *dropHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	h.cfg = options
	// TODO use global logger
	h.AllowList, err = filters.BuildFilterList(context.Background(), h.cfg.IncludeFilters, filters.DefaultFilters(logrus.New()))
	h.DenyList, err = filters.BuildFilterList(context.Background(), h.cfg.ExcludeFilters, filters.DefaultFilters(logrus.New()))

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

func (h *dropHandler) Deinit(registry *prometheus.Registry) {
	registry.Unregister(h.drops)
}
