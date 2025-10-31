// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/intstr"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestRulesToPolicyEntries(t *testing.T) {
	lbls := labels.LabelArray{labels.NewLabel("foo", "bar", labels.LabelSourceK8s)}
	es := api.NewESFromLabels(labels.ParseSelectLabel("foo=bar"))
	nodeSelector := api.NewESFromLabels(labels.ParseSelectLabel("node=selector"))
	trueBool := true
	falseBool := false

	tests := []struct {
		name  string
		rules api.Rules
		want  types.PolicyEntries
	}{
		{
			name:  "empty rules",
			rules: api.Rules{},
			want:  types.PolicyEntries{},
		},
		{
			name: "ingress rule",
			rules: api.Rules{
				{
					EndpointSelector: es,
					Labels:           lbls,
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("from=endpoint"))},
								FromCIDR:      []api.CIDR{"192.168.1.0/24"},
							},
							ToPorts: []api.PortRule{
								{
									Ports: []api.PortProtocol{
										{Port: "80", Protocol: api.ProtoTCP},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: true,
					Ingress:     true,
					L3: types.PeerSelectorSlice{
						api.NewESFromLabels(labels.ParseSelectLabel("from=endpoint")),
						api.CIDR("192.168.1.0/24"),
					},
					L4: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{Port: "80", Protocol: api.ProtoTCP},
							},
						},
					},
				},
			},
		},
		{
			name: "ingress deny rule",
			rules: api.Rules{
				{
					EndpointSelector: es,
					Labels:           lbls,
					IngressDeny: []api.IngressDenyRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("from=endpoint"))},
							},
							ToPorts: []api.PortDenyRule{
								{
									Ports: []api.PortProtocol{
										{Port: "80", Protocol: api.ProtoTCP},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: true,
					Deny:        true,
					Ingress:     true,
					L3: types.PeerSelectorSlice{
						api.NewESFromLabels(labels.ParseSelectLabel("from=endpoint")),
					},
					L4: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{Port: "80", Protocol: api.ProtoTCP},
							},
						},
					},
				},
			},
		},
		{
			name: "egress rule",
			rules: api.Rules{
				{
					EndpointSelector: es,
					Labels:           lbls,
					Egress: []api.EgressRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("to=endpoint"))},
								ToCIDRSet:   []api.CIDRRule{{Cidr: "10.0.0.0/8"}},
							},
							ToPorts: []api.PortRule{
								{
									Ports: []api.PortProtocol{
										{Port: "53", Protocol: api.ProtoUDP},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: true,
					Ingress:     false,
					L3: types.PeerSelectorSlice{
						api.NewESFromLabels(labels.ParseSelectLabel("to=endpoint")),
						api.CIDRRule{Cidr: "10.0.0.0/8"},
					},
					L4: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{Port: "53", Protocol: api.ProtoUDP},
							},
						},
					},
				},
			},
		},
		{
			name: "egress deny rule",
			rules: api.Rules{
				{
					EndpointSelector: es,
					Labels:           lbls,
					EgressDeny: []api.EgressDenyRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("to=endpoint"))},
							},
							ToPorts: []api.PortDenyRule{
								{
									Ports: []api.PortProtocol{
										{Port: "53", Protocol: api.ProtoUDP},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: true,
					Deny:        true,
					Ingress:     false,
					L3: types.PeerSelectorSlice{
						api.NewESFromLabels(labels.ParseSelectLabel("to=endpoint")),
					},
					L4: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{Port: "53", Protocol: api.ProtoUDP},
							},
						},
					},
				},
			},
		},
		{
			name: "node selector",
			rules: api.Rules{
				{
					NodeSelector: nodeSelector,
					Labels:       lbls,
					Ingress: []api.IngressRule{
						{
							ToPorts: []api.PortRule{
								{
									Ports: []api.PortProtocol{
										{Port: "22", Protocol: api.ProtoTCP},
									},
								},
							},
						},
					},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     nodeSelector,
					Node:        true,
					Labels:      lbls,
					DefaultDeny: true,
					Ingress:     true,
					L3:          types.PeerSelectorSlice{},
					L4: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{Port: "22", Protocol: api.ProtoTCP},
							},
						},
					},
				},
			},
		},
		{
			name: "default deny disabled",
			rules: api.Rules{
				{
					EndpointSelector: es,
					Labels:           lbls,
					EnableDefaultDeny: api.DefaultDenyConfig{
						Ingress: &falseBool,
						Egress:  &falseBool,
					},
					Ingress: []api.IngressRule{{}},
					Egress:  []api.EgressRule{{}},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: false,
					Ingress:     true,
					L3:          types.PeerSelectorSlice{},
					L4:          api.PortRules{},
				},
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: false,
					Ingress:     false,
					L3:          types.PeerSelectorSlice{},
					L4:          api.PortRules{},
				},
			},
		},
		{
			name: "default deny partially enabled",
			rules: api.Rules{
				{
					EndpointSelector: es,
					Labels:           lbls,
					EnableDefaultDeny: api.DefaultDenyConfig{
						Ingress: &trueBool,
						Egress:  &falseBool,
					},
					Ingress: []api.IngressRule{{}},
					Egress:  []api.EgressRule{{}},
				},
			},
			want: types.PolicyEntries{
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: true,
					Ingress:     true,
					L3:          types.PeerSelectorSlice{},
					L4:          api.PortRules{},
				},
				{
					Subject:     es,
					Labels:      lbls,
					DefaultDeny: false,
					Ingress:     false,
					L3:          types.PeerSelectorSlice{},
					L4:          api.PortRules{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RulesToPolicyEntries(tt.rules)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMergeEndpointSelectors(t *testing.T) {
	endpoints := api.EndpointSelectorSlice{api.NewESFromLabels(labels.ParseSelectLabel("app=test"))}
	nodes := api.EndpointSelectorSlice{api.NewESFromLabels(labels.ParseSelectLabel("node=test"))}
	entities := api.EntitySlice{api.EntityHost}
	cidrSlice := api.CIDRSlice{"192.168.0.0/16"}
	cidrRuleSlice := api.CIDRRuleSlice{{Cidr: "10.0.0.0/8"}}
	fqdns := api.FQDNSelectorSlice{{MatchName: "example.com"}}

	tests := []struct {
		name          string
		endpoints     api.EndpointSelectorSlice
		nodes         api.EndpointSelectorSlice
		entities      api.EntitySlice
		cidrSlice     api.CIDRSlice
		cidrRuleSlice api.CIDRRuleSlice
		fqdns         api.FQDNSelectorSlice
		want          types.PeerSelectorSlice
	}{
		{
			name: "all nil",
			want: types.PeerSelectorSlice{},
		},
		{
			name:      "only endpoints",
			endpoints: endpoints,
			want:      types.ToPeerSelectorSlice(endpoints),
		},
		{
			name:  "only nodes",
			nodes: nodes,
			want:  types.ToPeerSelectorSlice(nodes),
		},
		{
			name:     "only entities",
			entities: entities,
			want:     types.ToPeerSelectorSlice(entities.GetAsEndpointSelectors()),
		},
		{
			name:      "only cidrSlice",
			cidrSlice: cidrSlice,
			want:      types.ToPeerSelectorSlice(cidrSlice),
		},
		{
			name:          "only cidrRuleSlice",
			cidrRuleSlice: cidrRuleSlice,
			want:          types.ToPeerSelectorSlice(cidrRuleSlice),
		},
		{
			name:  "only fqdns",
			fqdns: fqdns,
			want:  types.ToPeerSelectorSlice(fqdns),
		},
		{
			name:          "all present",
			endpoints:     endpoints,
			nodes:         nodes,
			entities:      entities,
			cidrSlice:     cidrSlice,
			cidrRuleSlice: cidrRuleSlice,
			fqdns:         fqdns,
			want: types.PeerSelectorSlice{
				endpoints[0],
				nodes[0],
				entities.GetAsEndpointSelectors()[0],
				cidrSlice[0],
				cidrRuleSlice[0],
				fqdns[0],
			},
		},
		{
			name:      "empty non-nil endpoints",
			endpoints: api.EndpointSelectorSlice{},
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeEndpointSelectors(tt.endpoints, tt.nodes, tt.entities, tt.cidrSlice, tt.cidrRuleSlice, tt.fqdns)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPortDenyRulesToPortRules(t *testing.T) {
	tests := []struct {
		name      string
		portRules api.PortDenyRules
		want      api.PortRules
	}{
		{
			name:      "empty",
			portRules: api.PortDenyRules{},
			want:      api.PortRules{},
		},
		{
			name: "single rule",
			portRules: api.PortDenyRules{
				{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				},
			},
			want: api.PortRules{
				{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				},
			},
		},
		{
			name: "multiple rules",
			portRules: api.PortDenyRules{
				{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				},
				{
					Ports: []api.PortProtocol{{Port: "443", Protocol: api.ProtoTCP}},
				},
			},
			want: api.PortRules{
				{
					Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				},
				{
					Ports: []api.PortProtocol{{Port: "443", Protocol: api.ProtoTCP}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portDenyRulesToPortRules(tt.portRules)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIcmpRules(t *testing.T) {
	icmpType := func(t int) *intstr.IntOrString {
		v := intstr.FromInt(t)
		return &v
	}
	tests := []struct {
		name      string
		icmpRules api.ICMPRules
		want      api.PortRules
	}{
		{
			name:      "empty",
			icmpRules: api.ICMPRules{},
			want:      api.PortRules{},
		},
		{
			name: "icmpv4",
			icmpRules: api.ICMPRules{
				{
					Fields: []api.ICMPField{{Type: icmpType(8), Family: "IPv4"}},
				},
			},
			want: api.PortRules{
				{
					Ports: []api.PortProtocol{{Port: "8", Protocol: api.ProtoICMP}},
				},
			},
		},
		{
			name: "icmpv6",
			icmpRules: api.ICMPRules{
				{
					Fields: []api.ICMPField{{Type: icmpType(128), Family: "IPv6"}},
				},
			},
			want: api.PortRules{
				{
					Ports: []api.PortProtocol{{Port: "128", Protocol: api.ProtoICMPv6}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := icmpRules(tt.icmpRules)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertToLabelSelectorRequirementSlice(t *testing.T) {
	tests := []struct {
		name      string
		selectors []api.EndpointSelector
		want      []slim_metav1.LabelSelectorRequirement
	}{
		{
			name:      "empty",
			selectors: []api.EndpointSelector{},
			want:      nil,
		},
		{
			name: "single selector",
			selectors: []api.EndpointSelector{
				api.NewESFromLabels(labels.ParseSelectLabel("foo=bar")),
			},
			want: []slim_metav1.LabelSelectorRequirement{
				{Key: "any.foo", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"bar"}},
			},
		},
		{
			name: "multiple selectors",
			selectors: []api.EndpointSelector{
				api.NewESFromLabels(labels.ParseSelectLabel("foo=bar")),
				api.NewESFromLabels(labels.ParseSelectLabel("baz=qux")),
			},
			want: []slim_metav1.LabelSelectorRequirement{
				{Key: "any.foo", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"bar"}},
				{Key: "any.baz", Operator: slim_metav1.LabelSelectorOpIn, Values: []string{"qux"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToLabelSelectorRequirementSlice(tt.selectors)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestGetSelector(t *testing.T) {
	endpointSelector := api.NewESFromLabels(labels.ParseSelectLabel("app=test"))
	nodeSelector := api.NewESFromLabels(labels.ParseSelectLabel("node=test"))

	tests := []struct {
		name     string
		rule     *api.Rule
		wantEs   api.EndpointSelector
		wantNode bool
	}{
		{
			name: "endpoint selector",
			rule: &api.Rule{
				EndpointSelector: endpointSelector,
			},
			wantEs:   endpointSelector,
			wantNode: false,
		},
		{
			name: "node selector",
			rule: &api.Rule{
				NodeSelector: nodeSelector,
			},
			wantEs:   nodeSelector,
			wantNode: true,
		},
		{
			name: "both selectors, node takes precedence",
			rule: &api.Rule{
				EndpointSelector: endpointSelector,
				NodeSelector:     nodeSelector,
			},
			wantEs:   nodeSelector,
			wantNode: true,
		},
		{
			name:     "no selector",
			rule:     &api.Rule{},
			wantEs:   api.EndpointSelector{},
			wantNode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEs, gotNode := getSelector(tt.rule)
			assert.Equal(t, tt.wantEs, gotEs)
			assert.Equal(t, tt.wantNode, gotNode)
		})
	}
}
