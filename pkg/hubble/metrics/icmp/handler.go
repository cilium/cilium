// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package icmp

import (
	"context"

	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type icmpHandler struct {
	icmp      *prometheus.CounterVec
	context   *api.ContextOptions
	cfg       *api.MetricConfig
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *icmpHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	h.cfg = options
	h.AllowList, err = filters.BuildFilterList(context.Background(), h.cfg.IncludeFilters, filters.DefaultFilters(logrus.New()))
	if err != nil {
		return err
	}
	h.DenyList, err = filters.BuildFilterList(context.Background(), h.cfg.ExcludeFilters, filters.DefaultFilters(logrus.New()))
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

func (h *icmpHandler) Deinit(registry *prometheus.Registry) bool {
	return registry.Unregister(h.icmp)
}
