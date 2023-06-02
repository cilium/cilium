// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net/netip"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (s *PolicyAPITestSuite) TestRequiresDerivativeRuleWithoutToGroups(c *C) {
	eg := EgressRule{}
	c.Assert(eg.RequiresDerivative(), Equals, false)
}

func (s *PolicyAPITestSuite) TestRequiresDerivativeRuleWithToGroups(c *C) {
	eg := EgressRule{}
	eg.ToGroups = []ToGroups{
		GetToGroupsRule(),
	}
	c.Assert(eg.RequiresDerivative(), Equals, true)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeRuleWithoutToGroups(c *C) {
	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToEndpoints: []EndpointSelector{
				{
					LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{
						"test": "true",
					},
					},
				},
			},
		},
	}
	newRule, err := eg.CreateDerivative(context.TODO())
	c.Assert(eg, checker.DeepEquals, newRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeRuleWithToGroupsWitInvalidRegisterCallback(c *C) {
	cb := func(ctx context.Context, group *ToGroups) ([]netip.Addr, error) {
		return []netip.Addr{}, fmt.Errorf("Invalid error")
	}
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []ToGroups{
				GetToGroupsRule(),
			},
		},
	}
	_, err := eg.CreateDerivative(context.TODO())
	c.Assert(err, NotNil)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeRuleWithToGroupsAndToPorts(c *C) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []ToGroups{
				GetToGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	c.Assert(eg.RequiresDerivative(), Equals, true)

	newRule, err := eg.CreateDerivative(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(len(newRule.ToGroups), Equals, 0)
	c.Assert(len(newRule.ToCIDRSet), Equals, 1)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeWithoutErrorAndNoIPs(c *C) {
	// Testing that if the len of the Ips returned by provider is 0 to block
	// all the IPS outside.
	cb := GetCallBackWithRule()
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []ToGroups{
				GetToGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	c.Assert(eg.RequiresDerivative(), Equals, true)

	newRule, err := eg.CreateDerivative(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(newRule, checker.DeepEquals, &EgressRule{})
}

func (s *PolicyAPITestSuite) TestIsLabelBasedEgress(c *C) {
	type args struct {
		eg *EgressRule
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
					eg: &EgressRule{
						EgressCommonRule: EgressCommonRule{
							ToEndpoints: []EndpointSelector{
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
					&EgressRule{
						EgressCommonRule: EgressCommonRule{
							ToCIDR: CIDRSlice{"192.0.0.0/3"},
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
					&EgressRule{
						EgressCommonRule: EgressCommonRule{
							ToCIDRSet: CIDRRuleSlice{
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
					&EgressRule{
						EgressCommonRule: EgressCommonRule{
							ToRequires: []EndpointSelector{
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
			name: "rule-with-services",
			setupArgs: func() args {

				svcLabels := map[string]string{
					"app": "tested-service",
				}
				selector := ServiceSelector(NewESFromMatchRequirements(svcLabels, nil))
				return args{
					&EgressRule{
						EgressCommonRule: EgressCommonRule{
							ToServices: []Service{
								{
									K8sServiceSelector: &K8sServiceSelectorNamespace{
										Selector:  selector,
										Namespace: "",
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
			name: "rule-with-fqdn",
			setupArgs: func() args {
				return args{
					&EgressRule{
						ToFQDNs: FQDNSelectorSlice{
							{
								MatchName: "cilium.io",
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
					&EgressRule{
						EgressCommonRule: EgressCommonRule{
							ToEntities: EntitySlice{
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
					&EgressRule{
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
			name: "rule-with-icmp",
			setupArgs: func() args {
				return args{
					&EgressRule{
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
					&EgressRule{
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
