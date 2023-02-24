// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"fmt"
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

func (d *policyHandler) Context() *api.ContextOptions {
	return d.context
}

func (d *policyHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{d.verdicts.MetricVec}
}

func (d *policyHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetEventType().GetType() == monitorAPI.MessageTypePolicyVerdict {
		return d.ProcessFlowL3L4(ctx, flow)
	}

	if flow.GetEventType().GetType() == monitorAPI.MessageTypeAccessLog {
		return d.ProcessFlowL7(ctx, flow)
	}

	return nil
}

func (d *policyHandler) ProcessFlowL3L4(ctx context.Context, flow *flowpb.Flow) error {
	// ignore verdict if the source is host since host is allowed to connect to any local endpoints.
	if flow.GetSource().GetIdentity() == uint32(identity.ReservedIdentityHost) {
		return nil
	}
	labelValues, err := d.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	direction := strings.ToLower(flow.GetTrafficDirection().String())
	match := strings.ToLower(monitorAPI.PolicyMatchType(flow.GetPolicyMatchType()).String())
	action := strings.ToLower(flow.Verdict.String())
	labels := []string{direction, match, action}
	labels = append(labels, labelValues...)

	d.verdicts.WithLabelValues(labels...).Inc()
	return nil
}

func (d *policyHandler) ProcessFlowL7(ctx context.Context, flow *flowpb.Flow) error {
	labelValues, err := d.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	direction := strings.ToLower(flow.GetTrafficDirection().String())
	var subType string
	if l7 := flow.GetL7(); l7 != nil {
		switch {
		case l7.GetDns() != nil:
			subType = "dns"
		case l7.GetHttp() != nil:
			subType = "http"
		case l7.GetKafka() != nil:
			subType = "kafka"
		}
	}
	match := fmt.Sprintf("l7/%s", subType)
	action := strings.ToLower(flow.Verdict.String())
	labels := []string{direction, match, action}
	labels = append(labels, labelValues...)

	d.verdicts.WithLabelValues(labels...).Inc()
	return nil
}
