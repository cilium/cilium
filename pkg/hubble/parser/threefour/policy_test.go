// Copyright 2019 Authors of Hubble
// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package threefour

import (
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/stretchr/testify/assert"
)

func TestFlowMatchesNetworkPolicy(t *testing.T) {
	np := &slim_networkingv1.NetworkPolicy{
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"bar": "baz"},
			},
			Ingress: []slim_networkingv1.NetworkPolicyIngressRule{
				{
					From: []slim_networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &slim_metav1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
					},
					Ports: []slim_networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8000}},
					},
				},
			},
		},
	}

	endpoint1 := &flow.Endpoint{Labels: []string{"k8s:foo=bar", "k8s:io.kubernetes.pod.namespace=default"}}
	endpoint2 := &flow.Endpoint{Labels: []string{"k8s:bar=baz", "k8s:io.kubernetes.pod.namespace=default"}}

	tcs := []struct {
		name    string
		flow    *flow.Flow
		matched bool
	}{
		{
			"unmatched l3",
			&flow.Flow{
				PolicyMatchType:  monitorAPI.PolicyMatchL3L4,
				TrafficDirection: flow.TrafficDirection_INGRESS,
				Source:           endpoint2,
				Destination:      endpoint1,
				L4:               &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{DestinationPort: 8000}}},
			},
			false,
		},
		{
			"unmatched l4",
			&flow.Flow{
				PolicyMatchType:  monitorAPI.PolicyMatchL3L4,
				TrafficDirection: flow.TrafficDirection_INGRESS,
				Source:           endpoint1,
				Destination:      endpoint2,
				L4:               &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{DestinationPort: 80}}},
			},
			false,
		},
		{
			"matched",
			&flow.Flow{
				PolicyMatchType:  monitorAPI.PolicyMatchL3L4,
				TrafficDirection: flow.TrafficDirection_INGRESS,
				Source:           endpoint1,
				Destination:      endpoint2,
				L4:               &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{DestinationPort: 8000}}},
			},
			true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.matched, flowMatchesNetworkPolicy(tc.flow, np))
		})
	}
}

func TestFlowMatchesRule(t *testing.T) {
	endpoint1 := &flow.Endpoint{Labels: []string{"foo=bar"}}
	endpoint2 := &flow.Endpoint{Labels: []string{"bar=baz"}}

	t.Run("L3 Matches", func(t *testing.T) {
		fl := &flow.Flow{
			PolicyMatchType:  monitorAPI.PolicyMatchL3Only,
			TrafficDirection: flow.TrafficDirection_EGRESS,
			Source:           endpoint1,
			Destination:      endpoint2,
		}
		rule := &api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo=bar")),
		}

		tcs := []struct {
			name     string
			selector api.EndpointSelector
			expected bool
		}{
			{"empty selector", api.EndpointSelector{}, false},
			{"wildcard selector", api.NewESFromLabels(), true},
			{"unmatched selector", api.NewESFromLabels(labels.ParseSelectLabel("foo=bar")), false},
			{"matched selector", api.NewESFromLabels(labels.ParseSelectLabel("bar=baz")), true},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				rule.Egress = []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToEndpoints: []api.EndpointSelector{tc.selector},
						},
					},
				}
				assert.Equal(t, tc.expected, flowMatchesRule(fl, rule))
			})
		}
	})

	t.Run("L4 Matches", func(t *testing.T) {
		fl := &flow.Flow{
			PolicyMatchType:  monitorAPI.PolicyMatchL4Only,
			TrafficDirection: flow.TrafficDirection_INGRESS,
			Source:           endpoint1,
			Destination:      endpoint2,
		}
		rule := &api.Rule{
			EndpointSelector: api.NewESFromLabels(),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "8000", Protocol: api.ProtoAny}}},
					},
				},
			},
		}

		tcs := []struct {
			name     string
			l4       *flow.Layer4
			expected bool
		}{
			{"unmatched TCP", &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{DestinationPort: 80}}}, false},
			{"matched TCP", &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{DestinationPort: 8000}}}, true},
			{"unmatched UDP", &flow.Layer4{Protocol: &flow.Layer4_UDP{UDP: &flow.UDP{DestinationPort: 80}}}, false},
			{"matched UDP", &flow.Layer4{Protocol: &flow.Layer4_UDP{UDP: &flow.UDP{DestinationPort: 8000}}}, true},
			{"unmatched ICMPv4", &flow.Layer4{Protocol: &flow.Layer4_ICMPv4{}}, false},
			{"unmatched ICMPv6", &flow.Layer4{Protocol: &flow.Layer4_ICMPv6{}}, false},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				fl.L4 = tc.l4
				assert.Equal(t, tc.expected, flowMatchesRule(fl, rule))
			})
		}
	})

	t.Run("L3+L4 Matches", func(t *testing.T) {
		fl := &flow.Flow{
			PolicyMatchType:  monitorAPI.PolicyMatchL3L4,
			TrafficDirection: flow.TrafficDirection_INGRESS,
			Source:           endpoint1,
			Destination:      endpoint2,
			L4:               &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{DestinationPort: 8000}}},
		}
		rule := &api.Rule{EndpointSelector: api.NewESFromLabels()}

		tcs := []struct {
			name     string
			iRule    api.IngressRule
			expected bool
		}{
			{
				"unmatched l3",
				api.IngressRule{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("bar=baz"))},
					},
					ToPorts: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "8000", Protocol: api.ProtoTCP}}},
					},
				},
				false,
			},
			{
				"unmatched l4",
				api.IngressRule{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("foo=bar"))},
					},
					ToPorts: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}},
					},
				},
				false,
			},
			{
				"matched l3+l4",
				api.IngressRule{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("foo=bar"))},
					},
					ToPorts: []api.PortRule{
						{Ports: []api.PortProtocol{{Port: "8000", Protocol: api.ProtoTCP}}},
					},
				},
				true,
			},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				rule.Ingress = []api.IngressRule{tc.iRule}
				assert.Equal(t, tc.expected, flowMatchesRule(fl, rule))
			})
		}
	})
}
