// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (s *PolicyAPITestSuite) TestIsLabelBasedIngress(c *C) {
	type args struct {
		eg *IngressRule
	}
	type wanted struct {
		isLabelBased bool
	}

	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
	}{
		{
			name: "label-based-rule",
			setupArgs: func() args {
				return args{
					eg: &IngressRule{
						IngressCommonRule: IngressCommonRule{
							FromEndpoints: []EndpointSelector{
								{
									LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{
										"test": "true",
									},
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "cidr-based-rule",
			setupArgs: func() args {
				return args{
					&IngressRule{
						IngressCommonRule: IngressCommonRule{
							FromCIDR: CIDRSlice{"192.0.0.0/3"},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "cidrset-based-rule",
			setupArgs: func() args {
				return args{
					&IngressRule{
						IngressCommonRule: IngressCommonRule{
							FromCIDRSet: CIDRRuleSlice{
								{
									Cidr: "192.0.0.0/3",
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "rule-with-requirements",
			setupArgs: func() args {
				return args{
					&IngressRule{
						IngressCommonRule: IngressCommonRule{
							FromRequires: []EndpointSelector{
								{
									LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{
										"test": "true",
									},
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: false,
				}
			},
		},
		{
			name: "rule-with-entities",
			setupArgs: func() args {
				return args{
					&IngressRule{
						IngressCommonRule: IngressCommonRule{
							FromEntities: EntitySlice{
								EntityHost,
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "rule-with-no-l3-specification",
			setupArgs: func() args {
				return args{
					&IngressRule{
						ToPorts: []PortRule{
							{
								Ports: []PortProtocol{
									{
										Port:     "80",
										Protocol: ProtoTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "rule-with-named-port",
			setupArgs: func() args {
				return args{
					&IngressRule{
						ToPorts: []PortRule{
							{
								Ports: []PortProtocol{
									{
										Port:     "port-80",
										Protocol: ProtoTCP,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "rule-with-icmp",
			setupArgs: func() args {
				return args{
					&IngressRule{
						ICMPs: ICMPRules{
							{
								Fields: []ICMPField{
									{
										Type: 8,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
		{
			name: "rule-with-icmp6",
			setupArgs: func() args {
				return args{
					&IngressRule{
						ICMPs: ICMPRules{
							{
								Fields: []ICMPField{
									{
										Family: IPv6Family,
										Type:   128,
									},
								},
							},
						},
					},
				}
			},
			setupWanted: func() wanted {
				return wanted{
					isLabelBased: true,
				}
			},
		},
	}

	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		c.Assert(args.eg.sanitize(), Equals, nil, Commentf("Test name: %q", tt.name))
		isLabelBased := args.eg.AllowsWildcarding()
		c.Assert(isLabelBased, checker.DeepEquals, want.isLabelBased, Commentf("Test name: %q", tt.name))
	}
}
