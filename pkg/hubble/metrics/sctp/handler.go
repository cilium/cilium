// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sctp

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

type sctpHandler struct {
	sctpChunkTypes *prometheus.CounterVec
	context        *api.ContextOptions
	AllowList      filters.FilterFuncs
	DenyList       filters.FilterFuncs
}

func (h *sctpHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	labels := []string{"chunk_type", "family"}
	labels = append(labels, h.context.GetLabelNames()...)

	h.sctpChunkTypes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "sctp_chunk_types_total",
		Help:      "SCTP chunk type occurrences",
	}, labels)

	registry.MustRegister(h.sctpChunkTypes)
	return nil
}

func (h *sctpHandler) Status() string {
	return h.context.Status()
}

func (h *sctpHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *sctpHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.sctpChunkTypes.MetricVec}
}

func (h *sctpHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if (flow.GetVerdict() != flowpb.Verdict_FORWARDED && flow.GetVerdict() != flowpb.Verdict_REDIRECTED) ||
		flow.GetL4() == nil {
		return nil
	}
	ip := flow.GetIP()
	sctp := flow.GetL4().GetSCTP()
	if ip == nil || sctp == nil {
		return nil
	}

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	contextLabels, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}
	labels := append([]string{"", ip.IpVersion.String()}, contextLabels...)

	if sctp.ChunkType != flowpb.SCTPChunkType_UNSUPPORTED {
		labels[0] = sctp.ChunkType.String()
		h.sctpChunkTypes.WithLabelValues(labels...).Inc()
	}

	return nil
}

func (h *sctpHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.sctpChunkTypes) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "sctp_chunk_types_total"))
	}
	return errs
}

func (h *sctpHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *sctpHandler) SetFilters(cfg *api.MetricConfig) error {
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
