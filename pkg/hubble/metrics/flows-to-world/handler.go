// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package flows_to_world

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	pkglabels "github.com/cilium/cilium/pkg/labels"

	"github.com/prometheus/client_golang/prometheus"
)

type flowsToWorldHandler struct {
	flowsToWorld *prometheus.CounterVec
	context      *api.ContextOptions
	worldLabel   string
	anyDrop      bool
	port         bool
}

func (h *flowsToWorldHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	h.context = c
	for key := range options {
		switch strings.ToLower(key) {
		case "any-drop":
			h.anyDrop = true
		case "port":
			h.port = true
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
	h.worldLabel = fmt.Sprintf("%s:%s", pkglabels.LabelSourceReserved, pkglabels.IDNameWorld)
	registry.MustRegister(h.flowsToWorld)
	return nil
}

func (h *flowsToWorldHandler) Status() string {
	return h.context.Status()
}

func (h *flowsToWorldHandler) isReservedWorld(endpoint *flowpb.Endpoint) bool {
	for _, label := range endpoint.Labels {
		if label == h.worldLabel {
			return true
		}
	}
	return false
}

func (h *flowsToWorldHandler) ProcessFlow(_ context.Context, flow *flowpb.Flow) {
	l4 := flow.GetL4()
	if flow.GetDestination() == nil ||
		!h.isReservedWorld(flow.GetDestination()) ||
		flow.GetEventType() == nil ||
		l4 == nil {
		return
	}
	// if "any-drop" option is not set, non-policy drops are ignored.
	if flow.GetVerdict() == flowpb.Verdict_DROPPED && !h.anyDrop && flow.GetDropReasonDesc() != flowpb.DropReason_POLICY_DENIED {
		return
	}
	// if this is potentially a forwarded reply packet, ignore it to avoid collecting statistics about ephemeral ports
	isReply := flow.GetIsReply() == nil || flow.GetIsReply().GetValue()
	if flow.GetVerdict() != flowpb.Verdict_DROPPED && isReply {
		return
	}
	labels := []string{v1.FlowProtocol(flow), flow.GetVerdict().String()}

	// if "port" option is set, add port to the label.
	if h.port {
		port := ""
		if tcp := l4.GetTCP(); tcp != nil {
			port = strconv.Itoa(int(tcp.GetDestinationPort()))
		} else if udp := l4.GetUDP(); udp != nil {
			port = strconv.Itoa(int(udp.GetDestinationPort()))
		}
		labels = append(labels, port)
	}
	labels = append(labels, h.context.GetLabelValues(flow)...)
	h.flowsToWorld.WithLabelValues(labels...).Inc()
}
