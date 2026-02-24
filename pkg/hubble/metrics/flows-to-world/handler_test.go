// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flows_to_world

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/ir"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestFlowsToWorldHandler_MatchingFlow(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"dns", "ip"},
			},
		},
	}

	h := &flowsToWorldHandler{}
	assert.NoError(t, h.Init(registry, opts))
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, strings.NewReader("")))
	flow := ir.Flow{
		Verdict:        flowpb.Verdict_DROPPED,
		DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
		EventType:      ir.EventType{Type: monitorAPI.MessageTypeDrop},
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80},
		},
		Source: ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		DestinationNames: []string{"cilium.io"},
	}

	h.ProcessFlow(t.Context(), &flow)
	flow.L4 = ir.Layer4{
		UDP: ir.UDP{DestinationPort: 53},
	}
	h.ProcessFlow(t.Context(), &flow)
	flow.L4 = ir.Layer4{
		ICMPv4: ir.ICMP{Type: 1},
	}
	h.ProcessFlow(t.Context(), &flow)
	flow.L4 = ir.Layer4{
		ICMPv6: ir.ICMP{Type: 1},
	}
	h.ProcessFlow(t.Context(), &flow)
	expected := strings.NewReader(`# HELP hubble_flows_to_world_total Total number of flows to reserved:world
# TYPE hubble_flows_to_world_total counter
hubble_flows_to_world_total{destination="cilium.io",protocol="ICMPv4",source="src-a",verdict="DROPPED"} 1
hubble_flows_to_world_total{destination="cilium.io",protocol="ICMPv6",source="src-a",verdict="DROPPED"} 1
hubble_flows_to_world_total{destination="cilium.io",protocol="UDP",source="src-a",verdict="DROPPED"} 1
hubble_flows_to_world_total{destination="cilium.io",protocol="TCP",source="src-a",verdict="DROPPED"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, expected))
}

func TestFlowsToWorldHandler_NonMatchingFlows(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"dns", "ip"},
			},
		},
	}
	h := &flowsToWorldHandler{}
	assert.NoError(t, h.Init(registry, opts))

	// destination is missing.
	h.ProcessFlow(t.Context(), &ir.Flow{
		Verdict: flowpb.Verdict_FORWARDED,
		Source:  ir.Endpoint{Namespace: "src-a"},
	})
	// destination is not reserved:world
	h.ProcessFlow(t.Context(), &ir.Flow{
		Verdict: flowpb.Verdict_FORWARDED,
		Source:  ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:host"},
		},
	})
	// L4 information is missing.
	h.ProcessFlow(t.Context(), &ir.Flow{
		Verdict: flowpb.Verdict_FORWARDED,
		Source:  ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
	})
	// EventType is missing.
	h.ProcessFlow(t.Context(), &ir.Flow{
		Verdict: flowpb.Verdict_FORWARDED,
		Source:  ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80},
		},
	})
	// Drop reason is not "Policy denied".
	h.ProcessFlow(t.Context(), &ir.Flow{
		Verdict:        flowpb.Verdict_DROPPED,
		EventType:      ir.EventType{Type: monitorAPI.MessageTypeDrop},
		DropReasonDesc: flowpb.DropReason_STALE_OR_UNROUTABLE_IP,
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80},
		},
		Source: ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		DestinationNames: []string{"cilium.io"},
	})
	// Flow is a reply.
	h.ProcessFlow(t.Context(), &ir.Flow{
		Verdict:   flowpb.Verdict_FORWARDED,
		EventType: ir.EventType{Type: monitorAPI.MessageTypeTrace},
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80},
		},
		Source: ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		DestinationNames: []string{"cilium.io"},
		Reply:            ir.ReplyYes,
	})
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, strings.NewReader("")))
}

func TestFlowsToWorldHandler_AnyDrop(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"dns", "ip"},
			},
			{
				Name:   "any-drop",
				Values: []string{""},
			},
		},
	}
	h := &flowsToWorldHandler{}
	assert.NoError(t, h.Init(registry, opts))
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, strings.NewReader("")))
	flow := ir.Flow{
		Verdict:        flowpb.Verdict_DROPPED,
		DropReasonDesc: flowpb.DropReason_STALE_OR_UNROUTABLE_IP,
		EventType:      ir.EventType{Type: monitorAPI.MessageTypeDrop},
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80},
		},
		Source: ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		DestinationNames: []string{"cilium.io"},
	}
	h.ProcessFlow(t.Context(), &flow)
	expected := strings.NewReader(`# HELP hubble_flows_to_world_total Total number of flows to reserved:world
# TYPE hubble_flows_to_world_total counter
hubble_flows_to_world_total{destination="cilium.io",protocol="TCP",source="src-a",verdict="DROPPED"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, expected))
}

func TestFlowsToWorldHandler_IncludePort(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"dns", "ip"},
			},
			{
				Name:   "port",
				Values: []string{""},
			},
		},
	}
	h := &flowsToWorldHandler{}
	assert.NoError(t, h.Init(registry, opts))
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, strings.NewReader("")))
	flow := ir.Flow{
		Verdict:   flowpb.Verdict_FORWARDED,
		EventType: ir.EventType{Type: monitorAPI.MessageTypeTrace},
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80},
		},
		Source: ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		DestinationNames: []string{"cilium.io"},
		Reply:            ir.ReplyNo,
	}
	h.ProcessFlow(t.Context(), &flow)
	flow.L4 = ir.Layer4{
		UDP: ir.UDP{DestinationPort: 53},
	}
	h.ProcessFlow(t.Context(), &flow)
	flow.L4 = ir.Layer4{
		SCTP: ir.SCTP{DestinationPort: 2905},
	}
	h.ProcessFlow(t.Context(), &flow)
	expected := strings.NewReader(`# HELP hubble_flows_to_world_total Total number of flows to reserved:world
# TYPE hubble_flows_to_world_total counter
hubble_flows_to_world_total{destination="cilium.io",port="2905",protocol="SCTP",source="src-a",verdict="FORWARDED"} 1
hubble_flows_to_world_total{destination="cilium.io",port="80",protocol="TCP",source="src-a",verdict="FORWARDED"} 1
hubble_flows_to_world_total{destination="cilium.io",port="53",protocol="UDP",source="src-a",verdict="FORWARDED"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, expected))
}

func TestFlowsToWorldHandler_SynOnly(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts := &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{
				Name:   "sourceContext",
				Values: []string{"namespace"},
			},
			{
				Name:   "destinationContext",
				Values: []string{"dns", "ip"},
			},
			{
				Name:   "syn-only",
				Values: []string{""},
			},
		},
	}
	h := &flowsToWorldHandler{}
	assert.NoError(t, h.Init(registry, opts))
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, strings.NewReader("")))
	flow := ir.Flow{
		Verdict:        flowpb.Verdict_DROPPED,
		DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
		EventType:      ir.EventType{Type: monitorAPI.MessageTypeDrop},
		L4: ir.Layer4{
			TCP: ir.TCP{DestinationPort: 80, Flags: ir.TCPFlags{SYN: true}},
		},
		Source: ir.Endpoint{Namespace: "src-a"},
		Destination: ir.Endpoint{
			Labels: []string{"reserved:world"},
		},
		DestinationNames: []string{"cilium.io"},
		Reply:            ir.ReplyNo,
	}
	h.ProcessFlow(t.Context(), &flow)

	// flows without is_reply field should be counted.
	flow.Reply = ir.ReplyUnknown
	h.ProcessFlow(t.Context(), &flow)

	// reply flows should not be counted
	flow.Reply = ir.ReplyYes
	h.ProcessFlow(t.Context(), &flow)

	// Non-SYN should not be counted
	flow.Reply = ir.ReplyNo
	flow.L4.TCP.Flags = ir.TCPFlags{ACK: true}
	h.ProcessFlow(t.Context(), &flow)

	expected := strings.NewReader(`# HELP hubble_flows_to_world_total Total number of flows to reserved:world
# TYPE hubble_flows_to_world_total counter
hubble_flows_to_world_total{destination="cilium.io",protocol="TCP",source="src-a",verdict="DROPPED"} 2
`)
	assert.NoError(t, testutil.CollectAndCompare(h.flowsToWorld, expected))
}

func Test_flowsToWorldHandler_Status(t *testing.T) {
	h := &flowsToWorldHandler{
		context: &api.ContextOptions{
			Destination: api.ContextIdentifierList{api.ContextNamespace},
			Source:      api.ContextIdentifierList{api.ContextReservedIdentity},
		},
		anyDrop: true,
		port:    true,
		synOnly: true,
	}
	assert.Equal(t, "any-drop,port,syn-only,destination=namespace,source=reserved-identity", h.Status())
	h.anyDrop = false
	h.port = false
	assert.Equal(t, "syn-only,destination=namespace,source=reserved-identity", h.Status())
}
