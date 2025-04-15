// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package icmp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type icmpHandler struct {
	icmp      *prometheus.CounterVec
	context   *api.ContextOptions
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *icmpHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	labels := []string{"family", "type"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.icmp = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "icmp_total",
		Help:      "Number of ICMP messages",
	}, labels)

	registry.MustRegister(h.icmp)
	return nil
}

func (h *icmpHandler) Status() string {
	return h.context.Status()
}

func (h *icmpHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *icmpHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.icmp.MetricVec}
}

func (h *icmpHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	l4 := flow.GetL4()
	if l4 == nil {
		return nil
	}

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	if icmp := l4.GetICMPv4(); icmp != nil {
		labels := []string{"IPv4", layers.CreateICMPv4TypeCode(uint8(icmp.Type), uint8(icmp.Code)).String()}
		labels = append(labels, labelValues...)
		h.icmp.WithLabelValues(labels...).Inc()
	}

	if icmp := l4.GetICMPv6(); icmp != nil {
		labels := []string{"IPv4", layers.CreateICMPv6TypeCode(uint8(icmp.Type), uint8(icmp.Code)).String()}
		labels = append(labels, labelValues...)
		h.icmp.WithLabelValues(labels...).Inc()
	}

	return nil
}

func (h *icmpHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.icmp) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "icmp_total"))
	}
	return errs
}

func (h *icmpHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *icmpHandler) SetFilters(cfg *api.MetricConfig) error {
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
