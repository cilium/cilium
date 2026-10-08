// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flows_to_world

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	pkglabels "github.com/cilium/cilium/pkg/labels"
)

const (
	reservedWorldLbl     = pkglabels.LabelSourceReserved + ":" + pkglabels.IDNameWorld
	reservedWorldIPv4Lbl = pkglabels.LabelSourceReserved + ":" + pkglabels.IDNameWorldIPv4
	reservedWorldIPv6Lbl = pkglabels.LabelSourceReserved + ":" + pkglabels.IDNameWorldIPv6
)

type flowsToWorldHandler struct {
	flowsToWorld *prometheus.CounterVec
	context      *api.ContextOptions
	AllowList    filters.FilterFuncs
	DenyList     filters.FilterFuncs
	anyDrop      bool
	port         bool
	synOnly      bool
}

func (h *flowsToWorldHandler) Init(registry *prometheus.Registry, options *api.MetricConfig) error {
	c, err := api.ParseContextOptions(options.ContextOptionConfigs)
	if err != nil {
		return err
	}
	h.context = c
	err = h.HandleConfigurationUpdate(options)
	if err != nil {
		return err
	}

	for _, opt := range options.ContextOptionConfigs {
		switch strings.ToLower(opt.Name) {
		case "any-drop":
			h.anyDrop = true
		case "port":
			h.port = true
		case "syn-only":
			h.synOnly = true
		}
	}
	labels := []string{"protocol", "verdict"}
	if h.port {
		labels = append(labels, "port")
	}
	labels = append(labels, h.context.GetLabelNames()...)

	h.flowsToWorld = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "flows_to_world_total",
		Help:      "Total number of flows to reserved:world",
	}, labels)
	registry.MustRegister(h.flowsToWorld)
	return nil
}

func (h *flowsToWorldHandler) Status() string {
	var status []string
	if h.anyDrop {
		status = append(status, "any-drop")
	}
	if h.port {
		status = append(status, "port")
	}
	if h.synOnly {
		status = append(status, "syn-only")
	}
	return strings.Join(append(status, h.context.Status()), ",")
}

func (h *flowsToWorldHandler) Context() *api.ContextOptions {
	return h.context
}

func (h *flowsToWorldHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{h.flowsToWorld.MetricVec}
}

func (h *flowsToWorldHandler) isReservedWorld(endpoint *flowpb.Endpoint) bool {
	for _, label := range endpoint.Labels {
		switch label {
		case reservedWorldLbl, reservedWorldIPv4Lbl, reservedWorldIPv6Lbl:
			return true
		}
	}
	return false
}

func (h *flowsToWorldHandler) ProcessFlow(_ context.Context, flow *flowpb.Flow) error {
	l4 := flow.GetL4()
	if flow.GetDestination() == nil ||
		!h.isReservedWorld(flow.GetDestination()) ||
		flow.GetEventType() == nil ||
		l4 == nil {
		return nil
	}
	// if "any-drop" option is not set, non-policy drops are ignored.
	if flow.GetVerdict() == flowpb.Verdict_DROPPED && !h.anyDrop && flow.GetDropReasonDesc() != flowpb.DropReason_POLICY_DENIED {
		return nil
	}
	// if this is potentially a forwarded reply packet, ignore it to avoid collecting statistics about ephemeral ports
	isReply := flow.GetIsReply() != nil && flow.GetIsReply().GetValue()
	if flow.GetVerdict() != flowpb.Verdict_DROPPED && isReply {
		return nil
	}

	// if "syn-only" option is set, only count non-reply SYN packets for TCP.
	if h.synOnly && (!l4.GetTCP().GetFlags().GetSYN() || isReply) {
		return nil
	}

	if !filters.Apply(h.AllowList, h.DenyList, &v1.Event{Event: flow, Timestamp: &timestamppb.Timestamp{}}) {
		return nil
	}

	labelValues, err := h.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	labels := []string{v1.FlowProtocol(flow), flow.GetVerdict().String()}

	// if "port" option is set, add port to the label.
	if h.port {
		port := ""
		if tcp := l4.GetTCP(); tcp != nil {
			port = strconv.Itoa(int(tcp.GetDestinationPort()))
		} else if udp := l4.GetUDP(); udp != nil {
			port = strconv.Itoa(int(udp.GetDestinationPort()))
		} else if sctp := l4.GetSCTP(); sctp != nil {
			port = strconv.Itoa(int(sctp.GetDestinationPort()))
		}
		labels = append(labels, port)
	}
	labels = append(labels, labelValues...)
	h.flowsToWorld.WithLabelValues(labels...).Inc()
	return nil
}

func (h *flowsToWorldHandler) Deinit(registry *prometheus.Registry) error {
	var errs error
	if !registry.Unregister(h.flowsToWorld) {
		errs = errors.Join(errs, fmt.Errorf("failed to unregister metric: %v,", "flows_to_world_total"))
	}
	return errs
}

func (h *flowsToWorldHandler) HandleConfigurationUpdate(cfg *api.MetricConfig) error {
	return h.SetFilters(cfg)
}

func (h *flowsToWorldHandler) SetFilters(cfg *api.MetricConfig) error {
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
