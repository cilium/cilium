// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package flows_per_pod

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type flowsPerPodHandler struct {
	flowsPerPod *prometheus.CounterVec
	context     *api.ContextOptions
}

func (h *flowsPerPodHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c

	labels := []string{"protocol", "verdict"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.flowsPerPod = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "flows_per_pod_total",
		Help:      "Total number of flows per pod",
	}, labels)

	registry.MustRegister(h.flowsPerPod)

	return nil
}

func (h *flowsPerPodHandler) Status() string {
	return h.context.Status()
}

func (h *flowsPerPodHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *flowsPerPodHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.flowsPerPod.MetricVec}
}

func (h *flowsPerPodHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	labels := []string{v1.FlowProtocol(flow), flow.GetVerdict().String()}
	labels = append(labels, labelValues...)

	h.flowsPerPod.WithLabelValues(labels...).Inc()

	return nil
}
