// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package drop

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type dropHandler struct {
	drops   *prometheus.CounterVec
	context *api.ContextOptions
}

func (d *dropHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	d.context = c

	labels := []string{"reason", "protocol"}
	labels = append(labels, d.context.GetLabelNames()...)

	d.drops = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "drop_total",
		Help:      "Number of drops",
	}, labels)

	registry.MustRegister(d.drops)
	return nil
}

func (d *dropHandler) Status() string {
	return d.context.Status()
}

func (d *dropHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) {
	if flow.GetVerdict() != flowpb.Verdict_DROPPED {
		return
	}

	labels := []string{monitorAPI.DropReason(uint8(flow.GetDropReason())), v1.FlowProtocol(flow)}
	labels = append(labels, d.context.GetLabelValues(flow)...)

	d.drops.WithLabelValues(labels...).Inc()
}
