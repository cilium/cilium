// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package tcp

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type tcpHandler struct {
	tcpFlags *prometheus.CounterVec
	context  *api.ContextOptions
}

func (h *tcpHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c
	labels := []string{"flag", "family"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.tcpFlags = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "tcp_flags_total",
		Help:      "TCP flag occurrences",
	}, labels)

	registry.MustRegister(h.tcpFlags)
	return nil
}

func (h *tcpHandler) Status() string {
	return h.context.Status()
}

func (h *tcpHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *tcpHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.tcpFlags.MetricVec}
}

func (h *tcpHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if (flow.GetVerdict() != flowpb.Verdict_FORWARDED && flow.GetVerdict() != flowpb.Verdict_REDIRECTED) ||
		flow.GetL4() == nil {
		return nil
	}

	ip := flow.GetIP()
	tcp := flow.GetL4().GetTCP()
	if ip == nil || tcp == nil || tcp.Flags == nil {
		return nil
	}

	contextLabels, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}
	labels := append([]string{"", ip.IpVersion.String()}, contextLabels...)

	if tcp.Flags.FIN {
		labels[0] = "FIN"
		h.tcpFlags.WithLabelValues(labels...).Inc()
	}

	if tcp.Flags.SYN {
		if tcp.Flags.ACK {
			labels[0] = "SYN-ACK"
			h.tcpFlags.WithLabelValues(labels...).Inc()
		} else {
			labels[0] = "SYN"
			h.tcpFlags.WithLabelValues(labels...).Inc()
		}
	}

	if tcp.Flags.RST {
		labels[0] = "RST"
		h.tcpFlags.WithLabelValues(labels...).Inc()
	}

	return nil
}
