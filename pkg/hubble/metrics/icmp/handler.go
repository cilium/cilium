// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Hubble

package icmp

import (
	"context"

	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type icmpHandler struct {
	icmp    *prometheus.CounterVec
	context *api.ContextOptions
}

func (h *icmpHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

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

func (h *icmpHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) {
	l4 := flow.GetL4()
	if l4 == nil {
		return
	}

	if icmp := l4.GetICMPv4(); icmp != nil {
		labels := []string{"IPv4", layers.CreateICMPv4TypeCode(uint8(icmp.Type), uint8(icmp.Code)).String()}
		labels = append(labels, h.context.GetLabelValues(flow)...)
		h.icmp.WithLabelValues(labels...).Inc()
	}

	if icmp := l4.GetICMPv6(); icmp != nil {
		labels := []string{"IPv4", layers.CreateICMPv6TypeCode(uint8(icmp.Type), uint8(icmp.Code)).String()}
		labels = append(labels, h.context.GetLabelValues(flow)...)
		h.icmp.WithLabelValues(labels...).Inc()
	}
}
