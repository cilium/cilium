// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package portdistribution

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type portDistributionHandler struct {
	portDistribution *prometheus.CounterVec
	context          *api.ContextOptions
	AllowList        filters.FilterFuncs
	DenyList         filters.FilterFuncs
}

func (h *portDistributionHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	labels := []string{"protocol", "port"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.portDistribution = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "port_distribution_total",
		Help:      "Numbers of packets distributed by destination port",
	}, labels)

	registry.MustRegister(h.portDistribution)
	return nil
}

func (h *portDistributionHandler) Status() string {
	return h.context.Status()
}

func (h *portDistributionHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *portDistributionHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.portDistribution.MetricVec}
}

func (h *portDistributionHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	// if we are not certain if a flow is a reply (i.e. flow.GetIsReply() == nil)
	// we do not want to consider its destination port for the metric
	skipReply := flow.GetIsReply() == nil || flow.GetIsReply().GetValue()
	if (flow.GetVerdict() != flowpb.Verdict_FORWARDED && flow.GetVerdict() != flowpb.Verdict_REDIRECTED) ||
		flow.GetL4() == nil || skipReply {
		return nil
	}

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	if tcp := flow.GetL4().GetTCP(); tcp != nil {
		labels := append([]string{"TCP", fmt.Sprintf("%d", tcp.DestinationPort)}, labelValues...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if udp := flow.GetL4().GetUDP(); udp != nil {
		labels := append([]string{"UDP", fmt.Sprintf("%d", udp.DestinationPort)}, labelValues...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if sctp := flow.GetL4().GetSCTP(); sctp != nil {
		labels := append([]string{"SCTP", fmt.Sprintf("%d", sctp.DestinationPort)}, labelValues...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if flow.GetL4().GetICMPv4() != nil {
		labels := append([]string{"ICMPv4", "0"}, labelValues...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}

	if flow.GetL4().GetICMPv6() != nil {
		labels := append([]string{"ICMPv6", "0"}, labelValues...)
		h.portDistribution.WithLabelValues(labels...).Inc()
	}
	return nil
}

func (h *portDistributionHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.portDistribution) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "port_distribution_total"))
	}
	return errs
}

func (h *portDistributionHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *portDistributionHandler) SetFilters(cfg *api.MetricConfig) error {
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
