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
		npL3Ingested                float64
		npHostNPIngested            float64
		npDNSIngested               float64
		npToFQDNsIngested           float64
		npHTTPIngested              float64
		npHTTPHeaderMatchesIngested float64
		npOtherL7Ingested           float64
		npDenyPoliciesIngested      float64
		npIngressCIDRGroupIngested  float64
		npMutualAuthIngested        float64
		npTLSInspectionIngested     float64
		npSNIAllowListIngested      float64
		npNonDefaultDenyIngested    float64
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
					npL3Ingested: 1,
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
					npL3Ingested:               1,
					npIngressCIDRGroupIngested: 1,
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
					npL3Ingested:               1,
					npDenyPoliciesIngested:     1,
					npIngressCIDRGroupIngested: 1,
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
					npL3Ingested:         1,
					npHostNPIngested:     1,
					npMutualAuthIngested: 1,
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
					npL3Ingested:     1,
					npHostNPIngested: 1,
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
					npL3Ingested:           1,
					npHostNPIngested:       1,
					npDenyPoliciesIngested: 1,
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
					npL3Ingested:           1,
					npDenyPoliciesIngested: 1,
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
					npL3Ingested:           1,
					npDenyPoliciesIngested: 1,
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
					npL3Ingested:           1,
					npHostNPIngested:       1,
					npDenyPoliciesIngested: 1,
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
					npL3Ingested:           1,
					npHostNPIngested:       1,
					npDenyPoliciesIngested: 1,
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
					npL3Ingested:     1,
					npHostNPIngested: 1,
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
					npOtherL7Ingested: 1,
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
					ToFQDNs:        true,
					NonDefaultDeny: true,
				},
				wantMetrics: metrics{
					npToFQDNsIngested:        1,
					npNonDefaultDenyIngested: 1,
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
					npHTTPHeaderMatchesIngested: 1,
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
									ServerNames: []api.ServerName{""},
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
					npHTTPHeaderMatchesIngested: 1,
					npOtherL7Ingested:           1,
					npSNIAllowListIngested:      1,
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

			assert.Equalf(t, tt.want.wantMetrics.npL3Ingested, metrics.NPL3Ingested.WithLabelValues(actionAdd).Get(), "NPL3Ingested different")
			assert.Equalf(t, float64(0), metrics.NPL3Ingested.WithLabelValues(actionDel).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npHostNPIngested, metrics.NPHostNPIngested.WithLabelValues(actionAdd).Get(), "NPHostNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPHostNPIngested.WithLabelValues(actionDel).Get(), "NPHostNPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.WithLabelValues(actionAdd).Get(), "NPDNSIngested different")
			assert.Equalf(t, float64(0), metrics.NPDNSIngested.WithLabelValues(actionDel).Get(), "NPDNSIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npToFQDNsIngested, metrics.NPToFQDNsIngested.WithLabelValues(actionAdd).Get(), "NPToFQDNsIngested different")
			assert.Equalf(t, float64(0), metrics.NPToFQDNsIngested.WithLabelValues(actionDel).Get(), "NPToFQDNsIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPIngested, metrics.NPHTTPIngested.WithLabelValues(actionAdd).Get(), "NPHTTPIngested different")
			assert.Equalf(t, float64(0), metrics.NPHTTPIngested.WithLabelValues(actionDel).Get(), "NPHTTPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPHeaderMatchesIngested, metrics.NPHTTPHeaderMatchesIngested.WithLabelValues(actionAdd).Get(), "NPHTTPHeaderMatchesIngested different")
			assert.Equalf(t, float64(0), metrics.NPHTTPHeaderMatchesIngested.WithLabelValues(actionDel).Get(), "NPHTTPHeaderMatchesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npOtherL7Ingested, metrics.NPOtherL7Ingested.WithLabelValues(actionAdd).Get(), "NPOtherL7Ingested different")
			assert.Equalf(t, float64(0), metrics.NPOtherL7Ingested.WithLabelValues(actionDel).Get(), "NPOtherL7Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npDenyPoliciesIngested, metrics.NPDenyPoliciesIngested.WithLabelValues(actionAdd).Get(), "NPDenyPoliciesIngested different")
			assert.Equalf(t, float64(0), metrics.NPDenyPoliciesIngested.WithLabelValues(actionDel).Get(), "NPDenyPoliciesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npIngressCIDRGroupIngested, metrics.NPIngressCIDRGroupIngested.WithLabelValues(actionAdd).Get(), "IngressCIDRGroupIngested different")
			assert.Equalf(t, float64(0), metrics.NPIngressCIDRGroupIngested.WithLabelValues(actionDel).Get(), "IngressCIDRGroupIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npMutualAuthIngested, metrics.NPMutualAuthIngested.WithLabelValues(actionAdd).Get(), "MutualAuthIngested different")
			assert.Equalf(t, float64(0), metrics.NPMutualAuthIngested.WithLabelValues(actionDel).Get(), "MutualAuthIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npTLSInspectionIngested, metrics.NPTLSInspectionIngested.WithLabelValues(actionAdd).Get(), "TLSInspectionIngested different")
			assert.Equalf(t, float64(0), metrics.NPTLSInspectionIngested.WithLabelValues(actionDel).Get(), "TLSInspectionIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npSNIAllowListIngested, metrics.NPSNIAllowListIngested.WithLabelValues(actionAdd).Get(), "SNIAllowListIngested different")
			assert.Equalf(t, float64(0), metrics.NPSNIAllowListIngested.WithLabelValues(actionDel).Get(), "SNIAllowListIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npNonDefaultDenyIngested, metrics.NPNonDefaultDenyIngested.WithLabelValues(actionAdd).Get(), "NPNonDefaultDenyIngested different")
			assert.Equalf(t, float64(0), metrics.NPNonDefaultDenyIngested.WithLabelValues(actionDel).Get(), "NPNonDefaultDenyIngested different")

			metrics.DelRule(tt.args.r)

			assert.Equalf(t, tt.want.wantMetrics.npL3Ingested, metrics.NPL3Ingested.WithLabelValues(actionAdd).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npL3Ingested, metrics.NPL3Ingested.WithLabelValues(actionDel).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npHostNPIngested, metrics.NPHostNPIngested.WithLabelValues(actionAdd).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npHostNPIngested, metrics.NPHostNPIngested.WithLabelValues(actionDel).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.WithLabelValues(actionAdd).Get(), "NPDNSIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.WithLabelValues(actionDel).Get(), "NPDNSIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npToFQDNsIngested, metrics.NPToFQDNsIngested.WithLabelValues(actionAdd).Get(), "NPToFQDNsIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npToFQDNsIngested, metrics.NPToFQDNsIngested.WithLabelValues(actionDel).Get(), "NPToFQDNsIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPIngested, metrics.NPHTTPIngested.WithLabelValues(actionAdd).Get(), "NPHTTPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPIngested, metrics.NPHTTPIngested.WithLabelValues(actionDel).Get(), "NPHTTPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPHeaderMatchesIngested, metrics.NPHTTPHeaderMatchesIngested.WithLabelValues(actionAdd).Get(), "NPHTTPHeaderMatchesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npHTTPHeaderMatchesIngested, metrics.NPHTTPHeaderMatchesIngested.WithLabelValues(actionDel).Get(), "NPHTTPHeaderMatchesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npOtherL7Ingested, metrics.NPOtherL7Ingested.WithLabelValues(actionAdd).Get(), "NPOtherL7Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npOtherL7Ingested, metrics.NPOtherL7Ingested.WithLabelValues(actionDel).Get(), "NPOtherL7Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npDenyPoliciesIngested, metrics.NPDenyPoliciesIngested.WithLabelValues(actionAdd).Get(), "NPDenyPoliciesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDenyPoliciesIngested, metrics.NPDenyPoliciesIngested.WithLabelValues(actionDel).Get(), "NPDenyPoliciesIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npIngressCIDRGroupIngested, metrics.NPIngressCIDRGroupIngested.WithLabelValues(actionAdd).Get(), "NPIngressCIDRGroupIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npIngressCIDRGroupIngested, metrics.NPIngressCIDRGroupIngested.WithLabelValues(actionDel).Get(), "NPIngressCIDRGroupIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npMutualAuthIngested, metrics.NPMutualAuthIngested.WithLabelValues(actionAdd).Get(), "NPMutualAuthIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npMutualAuthIngested, metrics.NPMutualAuthIngested.WithLabelValues(actionDel).Get(), "NPMutualAuthIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npTLSInspectionIngested, metrics.NPTLSInspectionIngested.WithLabelValues(actionAdd).Get(), "NPTLSInspectionIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npTLSInspectionIngested, metrics.NPTLSInspectionIngested.WithLabelValues(actionDel).Get(), "NPTLSInspectionIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npSNIAllowListIngested, metrics.NPSNIAllowListIngested.WithLabelValues(actionAdd).Get(), "NPSNIAllowListIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npSNIAllowListIngested, metrics.NPSNIAllowListIngested.WithLabelValues(actionDel).Get(), "NPSNIAllowListIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npNonDefaultDenyIngested, metrics.NPNonDefaultDenyIngested.WithLabelValues(actionAdd).Get(), "NPNonDefaultDenyIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npNonDefaultDenyIngested, metrics.NPNonDefaultDenyIngested.WithLabelValues(actionDel).Get(), "NPNonDefaultDenyIngested different")

		})
	}
}
