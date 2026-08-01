// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library_test

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/cel/library"
)

// testFlowFilter compiles and evaluates a CEL expression against the given Flow.
// It asserts on expected compile errors, runtime errors, or result values.
func testFlowFilter(
	t *testing.T,
	expr string,
	flow *flowpb.Flow,
	expectResult ref.Val,
	expectRuntimeErr string,
	expectCompileErrs []string,
) {
	t.Helper()
	testCEL(t,
		[]cel.EnvOption{library.FlowFilter()},
		library.FlowVarName,
		expr,
		flow,
		expectResult, expectRuntimeErr, expectCompileErrs,
	)
}

func TestFlowFilter(t *testing.T) {
	cases := []struct {
		name              string
		expr              string
		flow              *flowpb.Flow
		expectResult      ref.Val
		expectRuntimeErr  string
		expectCompileErrs []string
	}{
		// --- Verdict ---
		{
			name:         "verdict int comparison — match",
			expr:         `_flow.verdict == 0`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_VERDICT_UNKNOWN},
			expectResult: trueVal,
		},
		{
			name:         "verdict int comparison — no match",
			expr:         `_flow.verdict == 0`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED},
			expectResult: falseVal,
		},
		{
			name:         "verdict enum — FORWARDED matches",
			expr:         `_flow.verdict == Verdict.FORWARDED`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED},
			expectResult: trueVal,
		},
		{
			name:         "verdict enum — DROPPED matches",
			expr:         `_flow.verdict == Verdict.DROPPED`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED},
			expectResult: trueVal,
		},
		{
			name:         "verdict enum — mismatch",
			expr:         `_flow.verdict == Verdict.FORWARDED`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED},
			expectResult: falseVal,
		},
		{
			name:         "verdict OR — first arm matches",
			expr:         `_flow.verdict == Verdict.FORWARDED || _flow.verdict == Verdict.TRANSLATED`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED},
			expectResult: trueVal,
		},
		{
			name:         "verdict OR — second arm matches",
			expr:         `_flow.verdict == Verdict.FORWARDED || _flow.verdict == Verdict.TRANSLATED`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_TRANSLATED},
			expectResult: trueVal,
		},
		{
			name:         "verdict OR — neither matches",
			expr:         `_flow.verdict == Verdict.FORWARDED || _flow.verdict == Verdict.TRANSLATED`,
			flow:         &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED},
			expectResult: falseVal,
		},

		// --- IP ---
		{
			name:         "IP source match",
			expr:         `_flow.IP.source == '1.1.1.1'`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1"}},
			expectResult: trueVal,
		},
		{
			name:         "IP source no match",
			expr:         `_flow.IP.source == '1.1.1.1'`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2"}},
			expectResult: falseVal,
		},
		{
			name:         "IP destination match",
			expr:         `_flow.IP.destination == '8.8.8.8'`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Destination: "8.8.8.8"}},
			expectResult: trueVal,
		},
		{
			name:         "IP source OR destination — source matches",
			expr:         `_flow.IP.source == '1.1.1.1' || _flow.IP.destination == '8.8.8.8'`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "10.0.0.2"}},
			expectResult: trueVal,
		},
		{
			name:         "IP source OR destination — destination matches",
			expr:         `_flow.IP.source == '1.1.1.1' || _flow.IP.destination == '8.8.8.8'`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Source: "10.0.0.1", Destination: "8.8.8.8"}},
			expectResult: trueVal,
		},
		{
			name:         "IP source OR destination — neither matches",
			expr:         `_flow.IP.source == '1.1.1.1' || _flow.IP.destination == '8.8.8.8'`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Source: "10.0.0.1", Destination: "10.0.0.2"}},
			expectResult: falseVal,
		},
		{
			name:         "IP encrypted flag true",
			expr:         `_flow.IP.encrypted == true`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Encrypted: true}},
			expectResult: trueVal,
		},
		{
			name:         "IP encrypted flag false",
			expr:         `_flow.IP.encrypted == true`,
			flow:         &flowpb.Flow{IP: &flowpb.IP{Encrypted: false}},
			expectResult: falseVal,
		},

		// --- L4 TCP ---
		{
			name:         "l4 TCP presence — TCP flow matches",
			expr:         `has(_flow.l4.TCP)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}}},
			expectResult: trueVal,
		},
		{
			name:         "l4 TCP presence — UDP flow does not match",
			expr:         `has(_flow.l4.TCP)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}}},
			expectResult: falseVal,
		},
		{
			name:         "l4 TCP destination port match",
			expr:         `has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(80)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}}},
			expectResult: trueVal,
		},
		{
			name:         "l4 TCP destination port no match",
			expr:         `has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(80)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}}},
			expectResult: falseVal,
		},
		{
			name:         "l4 TCP destination port OR — port 80 matches",
			expr:         `has(_flow.l4.TCP) && (_flow.l4.TCP.destination_port == uint(80) || _flow.l4.TCP.destination_port == uint(443))`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}}},
			expectResult: trueVal,
		},
		{
			name:         "l4 TCP destination port OR — port 443 matches",
			expr:         `has(_flow.l4.TCP) && (_flow.l4.TCP.destination_port == uint(80) || _flow.l4.TCP.destination_port == uint(443))`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}}},
			expectResult: trueVal,
		},
		{
			name:         "l4 TCP destination port OR — UDP flow does not match",
			expr:         `has(_flow.l4.TCP) && (_flow.l4.TCP.destination_port == uint(80) || _flow.l4.TCP.destination_port == uint(443))`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 80}}}},
			expectResult: falseVal,
		},
		{
			name:         "l4 TCP source port match",
			expr:         `has(_flow.l4.TCP) && _flow.l4.TCP.source_port == uint(12345)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 12345, DestinationPort: 80}}}},
			expectResult: trueVal,
		},

		// --- L4 UDP ---
		{
			name:         "l4 UDP presence — UDP flow matches",
			expr:         `has(_flow.l4.UDP)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}}},
			expectResult: trueVal,
		},
		{
			name:         "l4 UDP presence — TCP flow does not match",
			expr:         `has(_flow.l4.UDP)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}}},
			expectResult: falseVal,
		},
		{
			name:         "l4 UDP destination port match",
			expr:         `has(_flow.l4.UDP) && _flow.l4.UDP.destination_port == uint(53)`,
			flow:         &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}}},
			expectResult: trueVal,
		},

		// --- Endpoint ---
		{
			name:         "source namespace match",
			expr:         `_flow.source.namespace == 'default'`,
			flow:         &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "default"}},
			expectResult: trueVal,
		},
		{
			name:         "source namespace no match",
			expr:         `_flow.source.namespace == 'default'`,
			flow:         &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "kube-system"}},
			expectResult: falseVal,
		},
		{
			name:         "destination pod name match",
			expr:         `_flow.destination.pod_name == 'my-pod'`,
			flow:         &flowpb.Flow{Destination: &flowpb.Endpoint{PodName: "my-pod"}},
			expectResult: trueVal,
		},
		{
			name: "source and destination namespace match",
			expr: `_flow.source.namespace == 'frontend' && _flow.destination.namespace == 'backend'`,
			flow: &flowpb.Flow{
				Source:      &flowpb.Endpoint{Namespace: "frontend"},
				Destination: &flowpb.Endpoint{Namespace: "backend"},
			},
			expectResult: trueVal,
		},

		// --- TrafficDirection ---
		{
			name:         "traffic direction ingress matches",
			expr:         `_flow.traffic_direction == TrafficDirection.INGRESS`,
			flow:         &flowpb.Flow{TrafficDirection: flowpb.TrafficDirection_INGRESS},
			expectResult: trueVal,
		},
		{
			name:         "traffic direction egress matches",
			expr:         `_flow.traffic_direction == TrafficDirection.EGRESS`,
			flow:         &flowpb.Flow{TrafficDirection: flowpb.TrafficDirection_EGRESS},
			expectResult: trueVal,
		},
		{
			name:         "traffic direction no match",
			expr:         `_flow.traffic_direction == TrafficDirection.INGRESS`,
			flow:         &flowpb.Flow{TrafficDirection: flowpb.TrafficDirection_EGRESS},
			expectResult: falseVal,
		},

		// --- Combined expressions ---
		{
			name: "verdict AND traffic direction",
			expr: `_flow.verdict == Verdict.FORWARDED && _flow.traffic_direction == TrafficDirection.INGRESS`,
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
			},
			expectResult: trueVal,
		},
		{
			name: "verdict AND traffic direction — verdict mismatch",
			expr: `_flow.verdict == Verdict.FORWARDED && _flow.traffic_direction == TrafficDirection.INGRESS`,
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
			},
			expectResult: falseVal,
		},
		{
			name: "TCP to port 80 with FORWARDED verdict",
			expr: `has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(80) && _flow.verdict == Verdict.FORWARDED`,
			flow: &flowpb.Flow{
				Verdict: flowpb.Verdict_FORWARDED,
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}},
			},
			expectResult: trueVal,
		},
		{
			name: "TCP to port 80 with DROPPED verdict — no match",
			expr: `has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(80) && _flow.verdict == Verdict.FORWARDED`,
			flow: &flowpb.Flow{
				Verdict: flowpb.Verdict_DROPPED,
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}},
			},
			expectResult: falseVal,
		},
		{
			name: "source IP AND TCP port",
			expr: `_flow.IP.source == '10.0.0.1' && has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == uint(443)`,
			flow: &flowpb.Flow{
				IP: &flowpb.IP{Source: "10.0.0.1"},
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expectResult: trueVal,
		},
		{
			name:         "node name match",
			expr:         `_flow.node_name == 'node-1'`,
			flow:         &flowpb.Flow{NodeName: "node-1"},
			expectResult: trueVal,
		},
		{
			name:         "node name no match",
			expr:         `_flow.node_name == 'node-1'`,
			flow:         &flowpb.Flow{NodeName: "node-2"},
			expectResult: falseVal,
		},

		// --- Compile errors ---
		{
			name:              "unknown field is a compile error",
			expr:              `_flow.nonexistent_field == 0`,
			flow:              &flowpb.Flow{},
			expectCompileErrs: []string{"undefined field"},
		},
		{
			name:              "undeclared variable is a compile error",
			expr:              `flow.verdict == 0`,
			flow:              &flowpb.Flow{},
			expectCompileErrs: []string{"undeclared reference"},
		},
		{
			name:              "type mismatch on port comparison is a compile error",
			expr:              `has(_flow.l4.TCP) && _flow.l4.TCP.destination_port == 80`,
			flow:              &flowpb.Flow{},
			expectCompileErrs: []string{"no matching overload"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testFlowFilter(t, tc.expr, tc.flow, tc.expectResult, tc.expectRuntimeErr, tc.expectCompileErrs)
		})
	}
}
