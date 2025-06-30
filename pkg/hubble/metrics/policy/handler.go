// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/identity"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type policyHandler struct {
	verdicts  *prometheus.CounterVec
	context   *api.ContextOptions
	AllowList filters.FilterFuncs
	DenyList  filters.FilterFuncs
}

func (h *policyHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	labels := []string{"direction", "match", "action"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.verdicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "policy_verdicts_total",
		Help:      "Total number of Cilium network policy verdicts",
	}, labels)

	registry.MustRegister(h.verdicts)
	return nil
}

func (h *policyHandler) Status() string {
	return h.context.Status()
}

func (h *policyHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *policyHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.verdicts.MetricVec}
}

func (h *policyHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	if flow.GetEventType().GetType() == monitorAPI.MessageTypePolicyVerdict {
		return h.ProcessFlowL3L4(ctx, flow)
	}

	if flow.GetEventType().GetType() == monitorAPI.MessageTypeAccessLog {
		return h.ProcessFlowL7(ctx, flow)
	}

	return nil
}

func (h *policyHandler) ProcessFlowL3L4(ctx context.Context, flow *flowpb.Flow) error {
	// ignore verdict if the source is host since host is allowed to connect to any local endpoints.
	if flow.GetSource().GetIdentity() == uint32(identity.ReservedIdentityHost) {
		return nil
	}
	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	direction := strings.ToLower(flow.GetTrafficDirection().String())
	match := strings.ToLower(monitorAPI.PolicyMatchType(flow.GetPolicyMatchType()).String())
	action := strings.ToLower(flow.Verdict.String())
	labels := []string{direction, match, action}
	labels = append(labels, labelValues...)

	h.verdicts.WithLabelValues(labels...).Inc()
	return nil
}

func (h *policyHandler) ProcessFlowL7(ctx context.Context, flow *flowpb.Flow) error {
	labelValues, err := h.context.GetLabelValues(flow)
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

	h.verdicts.WithLabelValues(labels...).Inc()
	return nil
}

func (h *policyHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.verdicts) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "policy_verdicts_total"))
	}
	return errs
}

func (h *policyHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *policyHandler) SetFilters(cfg *api.MetricConfig) error {
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
