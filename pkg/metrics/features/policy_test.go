// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/policy/api"
)

func Test_ruleType(t *testing.T) {
	type args struct {
		r api.Rule
	}
	type metrics struct {
		npL3L4Ingested              float64
		npL3L4Present               float64
		npHostNPIngested            float64
		npHostNPPresent             float64
		npDNSIngested               float64
		npDNSPresent                float64
		npHTTPIngested              float64
		npHTTPPresent               float64
		npHTTPHeaderMatchesIngested float64
		npHTTPHeaderMatchesPresent  float64
		npOtherL7Ingested           float64
		npOtherL7Present            float64
		npDenyPoliciesIngested      float64
		npDenyPoliciesPresent       float64
		npIngressCIDRGroupIngested  float64
		npIngressCIDRGroupPresent   float64
		npMutualAuthIngested        float64
		npMutualAuthPresent         float64
		npTLSInspectionIngested     float64
		npTLSInspectionPresent      float64
		npSNIAllowListIngested      float64
		npSNIAllowListPresent       float64
		npDefaultDenyConfigIngested float64
		npDefaultDenyConfigPresent  float64
	}
	type wanted struct {
		wantRF      RuleFeatures
		wantMetrics metrics
	}
	tests := []struct {
		name string
		args args
		want wanted
	}{
		{
			name: "L3 from FromEndpoints",
			args: args{
				r: api.Rule{
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromEndpoints: []api.EndpointSelector{
									{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested: 1,
					npL3L4Present:  1,
				},
			},
		},
		{
			name: "L3 from FromCIDRSet with CIDRGroupRef",
			args: args{
				r: api.Rule{
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromCIDRSet: []api.CIDRRule{
									{CIDRGroupRef: "some-group-ref"},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:               true,
					IngressCIDRGroup: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:             1,
					npL3L4Present:              1,
					npIngressCIDRGroupIngested: 1,
					npIngressCIDRGroupPresent:  1,
				},
			},
		},
		{
			name: "L3 IngressDeny from FromCIDRSet with CIDRGroupRef",
			args: args{
				r: api.Rule{
					IngressDeny: []api.IngressDenyRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromCIDRSet: []api.CIDRRule{
									{CIDRGroupRef: "some-group-ref"},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:               true,
					Deny:             true,
					IngressCIDRGroup: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:             1,
					npL3L4Present:              1,
					npDenyPoliciesIngested:     1,
					npDenyPoliciesPresent:      1,
					npIngressCIDRGroupIngested: 1,
					npIngressCIDRGroupPresent:  1,
				},
			},
		},
		{
			name: "L3 from Ingress ToNodes",
			args: args{
				r: api.Rule{
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromNodes: []api.EndpointSelector{
									{},
								},
							},
							Authentication: &api.Authentication{
								Mode: api.AuthenticationModeRequired,
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:         true,
					Host:       true,
					MutualAuth: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:       1,
					npL3L4Present:        1,
					npHostNPIngested:     1,
					npHostNPPresent:      1,
					npMutualAuthIngested: 1,
					npMutualAuthPresent:  1,
				},
			},
		},
		{
			name: "L3 from Egress ToNodes",
			args: args{
				r: api.Rule{
					Egress: []api.EgressRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToNodes: []api.EndpointSelector{
									{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Host: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:   1,
					npL3L4Present:    1,
					npHostNPIngested: 1,
					npHostNPPresent:  1,
				},
			},
		},
		{
			name: "No L3 rule present",
			args: args{
				r: api.Rule{
					Ingress: []api.IngressRule{
						{
							IngressCommonRule: api.IngressCommonRule{},
						},
					},
					Egress: []api.EgressRule{
						{
							EgressCommonRule: api.EgressCommonRule{},
						},
					},
				},
			},
		},
		{
			name: "L3 from IngressDeny FromNodes",
			args: args{
				r: api.Rule{
					IngressDeny: []api.IngressDenyRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromNodes: []api.EndpointSelector{
									{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Host: true,
					Deny: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:         1,
					npL3L4Present:          1,
					npHostNPIngested:       1,
					npHostNPPresent:        1,
					npDenyPoliciesIngested: 1,
					npDenyPoliciesPresent:  1,
				},
			},
		},
		{
			name: "L3 from IngressDeny IsL3",
			args: args{
				r: api.Rule{
					IngressDeny: []api.IngressDenyRule{
						{
							IngressCommonRule: api.IngressCommonRule{
								FromCIDR: []api.CIDR{"192.168.0.0/24"},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Deny: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:         1,
					npL3L4Present:          1,
					npDenyPoliciesIngested: 1,
					npDenyPoliciesPresent:  1,
				},
			},
		},
		{
			name: "L3 from EgressDeny IsL3",
			args: args{
				r: api.Rule{
					EgressDeny: []api.EgressDenyRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToCIDR: []api.CIDR{"192.168.0.0/24"},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Deny: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:         1,
					npL3L4Present:          1,
					npDenyPoliciesIngested: 1,
					npDenyPoliciesPresent:  1,
				},
			},
		},
		{
			name: "L3 from EgressDeny ToNodes",
			args: args{
				r: api.Rule{
					EgressDeny: []api.EgressDenyRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToNodes: []api.EndpointSelector{
									{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Host: true,
					Deny: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:         1,
					npL3L4Present:          1,
					npHostNPIngested:       1,
					npHostNPPresent:        1,
					npDenyPoliciesIngested: 1,
					npDenyPoliciesPresent:  1,
				},
			},
		},
		{
			name: "Host from EgressDeny ToNodes",
			args: args{
				r: api.Rule{
					EgressDeny: []api.EgressDenyRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToNodes: []api.EndpointSelector{
									{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Host: true,
					Deny: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:         1,
					npL3L4Present:          1,
					npHostNPIngested:       1,
					npHostNPPresent:        1,
					npDenyPoliciesIngested: 1,
					npDenyPoliciesPresent:  1,
				},
			},
		},
		{
			name: "Host from Egress ToNodes",
			args: args{
				r: api.Rule{
					Egress: []api.EgressRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToNodes: []api.EndpointSelector{
									{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					L3:   true,
					Host: true,
				},
				wantMetrics: metrics{
					npL3L4Ingested:   1,
					npL3L4Present:    1,
					npHostNPIngested: 1,
					npHostNPPresent:  1,
				},
			},
		},
		{
			name: "DNS rules and other L7",
			args: args{
				r: api.Rule{
					Egress: []api.EgressRule{
						{
							ToPorts: api.PortRules{
								{
									Rules: &api.L7Rules{
										DNS: []api.PortRuleDNS{
											{
												MatchName: "cilium.io",
											},
										},
										Kafka: []kafka.PortRule{
											{},
										},
									},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					DNS:     true,
					OtherL7: true,
				},
				wantMetrics: metrics{
					npDNSIngested:     1,
					npDNSPresent:      1,
					npOtherL7Ingested: 1,
					npOtherL7Present:  1,
				},
			},
		},
		{
			name: "FQDN rules w/ default deny config",
			args: args{
				r: api.Rule{
					EnableDefaultDeny: api.DefaultDenyConfig{Ingress: func() *bool { a := true; return &a }()},
					Egress: []api.EgressRule{
						{
							ToFQDNs: api.FQDNSelectorSlice{
								{
									MatchName:    "cilium.io",
									MatchPattern: "",
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					DNS:            true,
					NonDefaultDeny: true,
				},
				wantMetrics: metrics{
					npDNSIngested:               1,
					npDNSPresent:                1,
					npDefaultDenyConfigIngested: 1,
					npDefaultDenyConfigPresent:  1,
				},
			},
		},
		{
			name: "HTTP ingress rules",
			args: args{
				r: api.Rule{
					Ingress: []api.IngressRule{
						{
							ToPorts: api.PortRules{
								{
									Rules: &api.L7Rules{
										HTTP: []api.PortRuleHTTP{
											{},
										},
									},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					HTTP: true,
				},
				wantMetrics: metrics{
					npHTTPIngested: 1,
					npHTTPPresent:  1,
				},
			},
		},
		{
			name: "HTTP egress rules",
			args: args{
				r: api.Rule{
					Egress: []api.EgressRule{
						{
							ToPorts: api.PortRules{
								{
									Rules: &api.L7Rules{
										HTTP: []api.PortRuleHTTP{
											{},
										},
									},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					HTTP: true,
				},
				wantMetrics: metrics{
					npHTTPIngested: 1,
					npHTTPPresent:  1,
				},
			},
		},
		{
			name: "HTTP matches ingress rules",
			args: args{
				r: api.Rule{
					Ingress: []api.IngressRule{
						{
							ToPorts: api.PortRules{
								{
									Rules: &api.L7Rules{
										HTTP: []api.PortRuleHTTP{
											{
												HeaderMatches: []*api.HeaderMatch{
													{},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					HTTP:              true,
					HTTPHeaderMatches: true,
				},
				wantMetrics: metrics{
					npHTTPIngested:              1,
					npHTTPPresent:               1,
					npHTTPHeaderMatchesIngested: 1,
					npHTTPHeaderMatchesPresent:  1,
				},
			},
		},
		{
			name: "HTTP matches egress rules, other L7 and SNI",
			args: args{
				r: api.Rule{
					Egress: []api.EgressRule{
						{
							ToPorts: api.PortRules{
								{
									ServerNames: []string{""},
									Rules: &api.L7Rules{
										HTTP: []api.PortRuleHTTP{
											{
												HeaderMatches: []*api.HeaderMatch{
													{},
												},
											},
										},
										L7: []api.PortRuleL7{
											{},
										},
									},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					HTTP:              true,
					HTTPHeaderMatches: true,
					OtherL7:           true,
					SNIAllowList:      true,
				},
				wantMetrics: metrics{
					npHTTPIngested:              1,
					npHTTPPresent:               1,
					npHTTPHeaderMatchesIngested: 1,
					npHTTPHeaderMatchesPresent:  1,
					npOtherL7Ingested:           1,
					npOtherL7Present:            1,
					npSNIAllowListIngested:      1,
					npSNIAllowListPresent:       1,
				},
			},
		},
		{
			name: "Rules matches on TLS",
			args: args{
				r: api.Rule{
					Egress: []api.EgressRule{
						{
							ToPorts: api.PortRules{
								{
									TerminatingTLS: &api.TLSContext{},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					TLSInspection: true,
				},
				wantMetrics: metrics{
					npTLSInspectionIngested: 1,
					npTLSInspectionPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := ruleType(tt.args.r)
			assert.Equalf(t, tt.want.wantRF, rt, "ruleType(%v)", tt.args.r)

			metrics := NewMetrics(true)
			metrics.AddRule(tt.args.r)

			assert.Equalf(t, tt.want.wantMetrics.npL3L4Ingested, metrics.NPL3L4Ingested.Get(), "NPL3L4Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npL3L4Present, metrics.NPL3L4Present.Get(), "NPL3L4Present different")
			assert.Equalf(t, tt.want.wantMetrics.npHostNPIngested, metrics.NPHostNPIngested.Get(), "NPHostNPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHostNPPresent, metrics.NPHostNPPresent.Get(), "NPHostNPPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.Get(), "NPDNSIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSPresent, metrics.NPDNSPresent.Get(), "NPDNSPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPIngested, metrics.NPHTTPIngested.Get(), "NPDNSIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPPresent, metrics.NPHTTPPresent.Get(), "NPDNSPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPHeaderMatchesIngested, metrics.NPHTTPHeaderMatchesIngested.Get(), "NPHTTPHeaderMatchesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPHeaderMatchesPresent, metrics.NPHTTPHeaderMatchesPresent.Get(), "NPHTTPHeaderMatchesPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npOtherL7Ingested, metrics.NPOtherL7Ingested.Get(), "OtherL7Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npOtherL7Present, metrics.NPOtherL7Present.Get(), "OtherL7Present different")
			assert.Equalf(t, tt.want.wantMetrics.npDenyPoliciesIngested, metrics.NPDenyPoliciesIngested.Get(), "DenyIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDenyPoliciesPresent, metrics.NPDenyPoliciesPresent.Get(), "DenyPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npIngressCIDRGroupIngested, metrics.NPIngressCIDRGroupIngested.Get(), "IngressCIDRGroupIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npIngressCIDRGroupPresent, metrics.NPIngressCIDRGroupPresent.Get(), "IngressCIDRGroupPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npMutualAuthIngested, metrics.NPMutualAuthIngested.Get(), "MutualAuthIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npMutualAuthPresent, metrics.NPMutualAuthPresent.Get(), "MutualAuthPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npTLSInspectionIngested, metrics.NPTLSInspectionIngested.Get(), "TLSInspectionIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npTLSInspectionPresent, metrics.NPTLSInspectionPresent.Get(), "TLSInspectionPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npSNIAllowListIngested, metrics.NPSNIAllowListIngested.Get(), "SNIAllowListIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npSNIAllowListPresent, metrics.NPSNIAllowListPresent.Get(), "SNIAllowListPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npDefaultDenyConfigIngested, metrics.NPNonDefaultDenyIngested.Get(), "DefaultDenyConfigIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDefaultDenyConfigPresent, metrics.NPNonDefaultDenyPresent.Get(), "DefaultDenyConfigPresent different")

			metrics.DelRule(tt.args.r)

			assert.Equalf(t, tt.want.wantMetrics.npL3L4Ingested, metrics.NPL3L4Ingested.Get(), "NPL3L4Ingested different")
			assert.Equalf(t, float64(0), metrics.NPL3L4Present.Get(), "NPL3L4Present different")
			assert.Equalf(t, tt.want.wantMetrics.npHostNPIngested, metrics.NPHostNPIngested.Get(), "NPHostNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPHostNPPresent.Get(), "NPHostNPPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.Get(), "NPHostNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPDNSPresent.Get(), "NPDNSPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPIngested, metrics.NPHTTPIngested.Get(), "NPHTTPIngested different")
			assert.Equalf(t, float64(0), metrics.NPHTTPPresent.Get(), "NPHTTPPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPHeaderMatchesIngested, metrics.NPHTTPHeaderMatchesIngested.Get(), "NPHTTPHeaderMatchesIngested different")
			assert.Equalf(t, float64(0), metrics.NPHTTPHeaderMatchesPresent.Get(), "NPHTTPHeaderMatchesPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npOtherL7Ingested, metrics.NPOtherL7Ingested.Get(), "OtherL7Ingested different")
			assert.Equalf(t, float64(0), metrics.NPOtherL7Present.Get(), "OtherL7Present different")
			assert.Equalf(t, tt.want.wantMetrics.npDenyPoliciesIngested, metrics.NPDenyPoliciesIngested.Get(), "DenyIngested different")
			assert.Equalf(t, float64(0), metrics.NPDenyPoliciesPresent.Get(), "DenyPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npIngressCIDRGroupIngested, metrics.NPIngressCIDRGroupIngested.Get(), "IngressCIDRGroupIngested different")
			assert.Equalf(t, float64(0), metrics.NPIngressCIDRGroupPresent.Get(), "IngressCIDRGroupPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npMutualAuthIngested, metrics.NPMutualAuthIngested.Get(), "MutualAuthIngested different")
			assert.Equalf(t, float64(0), metrics.NPMutualAuthPresent.Get(), "MutualAuthPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npTLSInspectionIngested, metrics.NPTLSInspectionIngested.Get(), "TLSInspectionIngested different")
			assert.Equalf(t, float64(0), metrics.NPTLSInspectionPresent.Get(), "TLSInspectionPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npSNIAllowListIngested, metrics.NPSNIAllowListIngested.Get(), "SNIAllowListIngested different")
			assert.Equalf(t, float64(0), metrics.NPSNIAllowListPresent.Get(), "SNIAllowListPresent different")
			assert.Equalf(t, tt.want.wantMetrics.npDefaultDenyConfigIngested, metrics.NPNonDefaultDenyIngested.Get(), "DefaultDenyConfigIngested different")
			assert.Equalf(t, float64(0), metrics.NPNonDefaultDenyPresent.Get(), "DefaultDenyConfigPresent different")

		})
	}
}
