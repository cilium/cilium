// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"testing"

	"fmt"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIngressRequiresDerivativeRuleWithoutToGroups(t *testing.T) {
	ig := IngressRule{}
	require.Equal(t, false, ig.RequiresDerivative())
}

func TestRequiresDerivativeRuleWithFromGroups(t *testing.T) {
	ig := IngressRule{}
	ig.FromGroups = []Groups{
		GetGroupsRule(),
	}
	require.Equal(t, true, ig.RequiresDerivative())
}

func TestCreateDerivativeRuleWithoutFromGroups(t *testing.T) {
	ig := &IngressRule{
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
	}
	newRule, err := ig.CreateDerivative(context.TODO())
	require.EqualValues(t, newRule, ig)
	require.Nil(t, err)
}

func TestCreateDerivativeRuleWithFromGroups(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	ig := &IngressRule{
		IngressCommonRule: IngressCommonRule{
			FromGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	require.Equal(t, true, ig.RequiresDerivative())

	newRule, err := ig.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.FromGroups))
	require.Equal(t, 1, len(newRule.FromCIDRSet))
}

func TestIsLabelBasedIngress(t *testing.T) {
	setUpSuite(t)

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
				icmpType := intstr.FromInt(8)
				return args{
					&IngressRule{
						ICMPs: ICMPRules{
							{
								Fields: []ICMPField{
									{
										Type: &icmpType,
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
				icmpType := intstr.FromInt(128)
				return args{
					&IngressRule{
						ICMPs: ICMPRules{
							{
								Fields: []ICMPField{
									{
										Family: IPv6Family,
										Type:   &icmpType,
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
		require.Equal(t, nil, args.eg.sanitize(), fmt.Sprintf("Test name: %q", tt.name))
		isLabelBased := args.eg.AllowsWildcarding()
		require.EqualValues(t, want.isLabelBased, isLabelBased, fmt.Sprintf("Test name: %q", tt.name))
	}
}

func TestIngressCommonRuleDeepEqual(t *testing.T) {
	testCases := []struct {
		name      string
		in, other *IngressCommonRule
		expected  bool
	}{
		{
			name:     "All fields are nil in both",
			in:       &IngressCommonRule{},
			other:    &IngressCommonRule{},
			expected: true,
		},
		{
			name: "All fields are empty in both",
			in: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
				FromCIDR:      []CIDR{},
				FromCIDRSet:   []CIDRRule{},
				FromEntities:  []Entity{},
			},
			other: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
				FromCIDR:      []CIDR{},
				FromCIDRSet:   []CIDRRule{},
				FromEntities:  []Entity{},
			},
			expected: true,
		},
		{
			name: "FromEndpoints is nil in left operand",
			in: &IngressCommonRule{
				FromEndpoints: nil,
			},
			other: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
			},
			expected: false,
		},
		{
			name: "FromEndpoints is empty in left operand",
			in: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
			},
			other: &IngressCommonRule{
				FromEndpoints: nil,
			},
			expected: false,
		},
		{
			name: "FromCIDR is nil in left operand",
			in: &IngressCommonRule{
				FromCIDR: nil,
			},
			other: &IngressCommonRule{
				FromCIDR: []CIDR{},
			},
			expected: false,
		},
		{
			name: "FromCIDR is empty in left operand",
			in: &IngressCommonRule{
				FromCIDR: []CIDR{},
			},
			other: &IngressCommonRule{
				FromCIDR: nil,
			},
			expected: false,
		},
		{
			name: "FromCIDRSet is nil in left operand",
			in: &IngressCommonRule{
				FromCIDRSet: nil,
			},
			other: &IngressCommonRule{
				FromCIDRSet: []CIDRRule{},
			},
			expected: false,
		},
		{
			name: "FromCIDRSet is empty in left operand",
			in: &IngressCommonRule{
				FromCIDRSet: []CIDRRule{},
			},
			other: &IngressCommonRule{
				FromCIDRSet: nil,
			},
			expected: false,
		},
		{
			name: "FromEntities is nil in left operand",
			in: &IngressCommonRule{
				FromEntities: nil,
			},
			other: &IngressCommonRule{
				FromEntities: []Entity{},
			},
			expected: false,
		},
		{
			name: "FromEntities is empty in left operand",
			in: &IngressCommonRule{
				FromEntities: []Entity{},
			},
			other: &IngressCommonRule{
				FromEntities: nil,
			},
			expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.in.DeepEqual(tc.other))
		})
	}
}
