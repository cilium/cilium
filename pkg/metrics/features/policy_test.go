// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/policy/api"
)

func Test_ruleType(t *testing.T) {
	type args struct {
		r api.Rule
	}
	type metrics struct {
		npL3Ingested  float64
		npDNSIngested float64
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
					L3: true,
				},
				wantMetrics: metrics{
					npL3Ingested: 1,
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
					L3: true,
				},
				wantMetrics: metrics{
					npL3Ingested: 1,
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
					L3: true,
				},
				wantMetrics: metrics{
					npL3Ingested: 1,
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
					L3: true,
				},
				wantMetrics: metrics{
					npL3Ingested: 1,
				},
			},
		},
		{
			name: "DNS rules",
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
									},
								},
							},
						},
					},
				},
			},
			want: wanted{
				wantRF: RuleFeatures{
					DNS: true,
				},
				wantMetrics: metrics{
					npDNSIngested: 1,
				},
			},
		},
		{
			name: "FQDN rules",
			args: args{
				r: api.Rule{
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
					DNS: true,
				},
				wantMetrics: metrics{
					npDNSIngested: 1,
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
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.WithLabelValues(actionAdd).Get(), "NPDNSIngested different")
			assert.Equalf(t, float64(0), metrics.NPDNSIngested.WithLabelValues(actionDel).Get(), "NPDNSIngested different")

			metrics.DelRule(tt.args.r)

			assert.Equalf(t, tt.want.wantMetrics.npL3Ingested, metrics.NPL3Ingested.WithLabelValues(actionAdd).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npL3Ingested, metrics.NPL3Ingested.WithLabelValues(actionDel).Get(), "NPL3Ingested different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.WithLabelValues(actionAdd).Get(), "NPDNSIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npDNSIngested, metrics.NPDNSIngested.WithLabelValues(actionDel).Get(), "NPDNSIngested different")
		})
	}
}
