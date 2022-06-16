// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/identity"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type policyHandler struct {
	verdicts *prometheus.CounterVec
	context  *api.ContextOptions
}

func (d *policyHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	d.context = c

	labels := []string{"direction", "match", "action"}
	labels = append(labels, d.context.GetLabelNames()...)

	d.verdicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "policy_verdicts_total",
		Help:      "Total number of Cilium network policy verdicts",
	}, labels)

	registry.MustRegister(d.verdicts)
	return nil
}

func (d *policyHandler) Status() string {
	return d.context.Status()
}

func (d *policyHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) {
	if flow.GetEventType().GetType() != monitorAPI.MessageTypePolicyVerdict {
		return
	}
	// ignore verdict if the source is host since host is allowed to connect to any local endpoints.
	if flow.GetSource().GetIdentity() == uint32(identity.ReservedIdentityHost) {
		return
	}

	direction := strings.ToLower(flow.GetTrafficDirection().String())
	match := strings.ToLower(monitorAPI.PolicyMatchType(flow.GetPolicyMatchType()).String())
	action := strings.ToLower(flow.Verdict.String())
	labels := []string{direction, match, action}
	labels = append(labels, d.context.GetLabelValues(flow)...)

	d.verdicts.WithLabelValues(labels...).Inc()
}
