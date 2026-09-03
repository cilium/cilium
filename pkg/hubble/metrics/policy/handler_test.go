// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/identity"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestPolicyHandler(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &policyHandler{}
	assert.NoError(t, h.Init(registry, &api.MetricConfig{}))
	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, strings.NewReader("")))
	flow := flowpb.Flow{
		EventType:        &flowpb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		PolicyMatchType:  monitorAPI.PolicyMatchNone,
		Verdict:          flowpb.Verdict_DROPPED,
	}

	h.ProcessFlow(t.Context(), &flow)
	flow.TrafficDirection = flowpb.TrafficDirection_INGRESS
	flow.PolicyMatchType = monitorAPI.PolicyMatchL3L4
	flow.Verdict = flowpb.Verdict_REDIRECTED
	h.ProcessFlow(t.Context(), &flow)

	// Policy verdicts from host shouldn't be counted.
	flow.PolicyMatchType = monitorAPI.PolicyMatchAll
	flow.Source = &flowpb.Endpoint{Identity: uint32(identity.ReservedIdentityHost)}
	h.ProcessFlow(t.Context(), &flow)

	// l7/http
	flow.EventType = &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog}
	flow.Verdict = flowpb.Verdict_DROPPED
	flow.L7 = &flowpb.Layer7{
		Record: &flowpb.Layer7_Http{Http: &flowpb.HTTP{
			Code:     0,
			Method:   "POST",
			Url:      "http://myhost/some/path",
			Protocol: "http/1.1",
		}}}
	h.ProcessFlow(t.Context(), &flow)

	expected := strings.NewReader(`# HELP hubble_policy_verdicts_total Total number of Cilium network policy verdicts
# TYPE hubble_policy_verdicts_total counter
hubble_policy_verdicts_total{action="dropped",direction="egress",match="none"} 1
hubble_policy_verdicts_total{action="redirected",direction="ingress",match="l3-l4"} 1
hubble_policy_verdicts_total{action="dropped",direction="ingress",match="l7/http"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, expected))
}

func TestPolicyHandlerWithProtocolAndPort(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &policyHandler{}
	assert.NoError(t, h.Init(registry, &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{
			{Name: "protocol"},
			{Name: "destination_port"},
		},
	}))

	flow := &flowpb.Flow{
		EventType:        &flowpb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		PolicyMatchType:  monitorAPI.PolicyMatchL3L4,
		Verdict:          flowpb.Verdict_DROPPED,
		L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
			DestinationPort: 443,
		}}},
	}
	h.ProcessFlow(t.Context(), flow)

	expected := strings.NewReader(`# HELP hubble_policy_verdicts_total Total number of Cilium network policy verdicts
# TYPE hubble_policy_verdicts_total counter
hubble_policy_verdicts_total{action="dropped",destination_port="443",direction="egress",match="l3-l4",protocol="TCP"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, expected))
	assert.Equal(t, "protocol,destination_port", h.Status())
}

func TestPolicyHandlerUsesL4ProtocolForL7Flows(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &policyHandler{}
	assert.NoError(t, h.Init(registry, &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{{Name: "protocol"}},
	}))

	flow := &flowpb.Flow{
		EventType:        &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
		TrafficDirection: flowpb.TrafficDirection_INGRESS,
		Verdict:          flowpb.Verdict_DROPPED,
		L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{}}},
		L7:               &flowpb.Layer7{Record: &flowpb.Layer7_Http{Http: &flowpb.HTTP{}}},
	}
	h.ProcessFlow(t.Context(), flow)

	expected := strings.NewReader(`# HELP hubble_policy_verdicts_total Total number of Cilium network policy verdicts
# TYPE hubble_policy_verdicts_total counter
hubble_policy_verdicts_total{action="dropped",direction="ingress",match="l7/http",protocol="TCP"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, expected))
}

func TestPolicyHandlerWithDestinationPortSkipsL7ReplyFlows(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &policyHandler{}
	assert.NoError(t, h.Init(registry, &api.MetricConfig{
		ContextOptionConfigs: []*api.ContextOptionConfig{{Name: "destination_port"}},
	}))

	flow := &flowpb.Flow{
		EventType:        &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog},
		TrafficDirection: flowpb.TrafficDirection_INGRESS,
		Verdict:          flowpb.Verdict_FORWARDED,
		IsReply:          wrapperspb.Bool(true),
		L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
			DestinationPort: 49152,
		}}},
		L7: &flowpb.Layer7{Record: &flowpb.Layer7_Http{Http: &flowpb.HTTP{}}},
	}
	h.ProcessFlow(t.Context(), flow)

	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, strings.NewReader("")))
}
