// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestRequiresDerivativeRuleWithoutToGroups(t *testing.T) {
	eg := EgressRule{}
	require.Equal(t, false, eg.RequiresDerivative())
}

func TestRequiresDerivativeRuleWithToGroups(t *testing.T) {
	eg := EgressRule{}
	eg.ToGroups = []Groups{
		GetGroupsRule(),
	}
	require.Equal(t, true, eg.RequiresDerivative())
}

func TestCreateDerivativeRuleWithoutToGroups(t *testing.T) {
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
	require.EqualValues(t, newRule, eg)
	require.Nil(t, err)
}

func TestCreateDerivativeRuleWithToGroupsWitInvalidRegisterCallback(t *testing.T) {
	cb := func(ctx context.Context, group *Groups) ([]netip.Addr, error) {
		return []netip.Addr{}, fmt.Errorf("Invalid error")
	}
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}
	_, err := eg.CreateDerivative(context.TODO())
	require.Error(t, err)
}

func TestCreateDerivativeRuleWithToGroupsAndToPorts(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	require.Equal(t, true, eg.RequiresDerivative())

	newRule, err := eg.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.ToGroups))
	require.Equal(t, 1, len(newRule.ToCIDRSet))
}

func TestCreateDerivativeWithoutErrorAndNoIPs(t *testing.T) {
	// Testing that if the len of the Ips returned by provider is 0 to block
	// all the IPS outside.
	cb := GetCallBackWithRule()
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	require.Equal(t, true, eg.RequiresDerivative())

	newRule, err := eg.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.EqualValues(t, &EgressRule{}, newRule)
}

func TestIsLabelBasedEgress(t *testing.T) {
	setUpSuite(t)

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
				icmpType := intstr.FromInt(8)
				return args{
					&EgressRule{
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
					&EgressRule{
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

func TestEgressCommonRuleDeepEqual(t *testing.T) {
	testCases := []struct {
		name      string
		in, other *EgressCommonRule
		expected  bool
	}{
		{
			name:     "All fields are nil in both",
			in:       &EgressCommonRule{},
			other:    &EgressCommonRule{},
			expected: true,
		},
		{
			name: "All fields are empty in both",
			in: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
				ToCIDR:      []CIDR{},
				ToCIDRSet:   []CIDRRule{},
				ToEntities:  []Entity{},
			},
			other: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
				ToCIDR:      []CIDR{},
				ToCIDRSet:   []CIDRRule{},
				ToEntities:  []Entity{},
			},
			expected: true,
		},
		{
			name: "ToEndpoints is nil in left operand",
			in: &EgressCommonRule{
				ToEndpoints: nil,
			},
			other: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
			},
			expected: false,
		},
		{
			name: "ToEndpoints is empty in left operand",
			in: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
			},
			other: &EgressCommonRule{
				ToEndpoints: nil,
			},
			expected: false,
		},
		{
			name: "ToCIDR is nil in left operand",
			in: &EgressCommonRule{
				ToCIDR: nil,
			},
			other: &EgressCommonRule{
				ToCIDR: []CIDR{},
			},
			expected: false,
		},
		{
			name: "ToCIDR is empty in left operand",
			in: &EgressCommonRule{
				ToCIDR: []CIDR{},
			},
			other: &EgressCommonRule{
				ToCIDR: nil,
			},
			expected: false,
		},
		{
			name: "ToCIDRSet is nil in left operand",
			in: &EgressCommonRule{
				ToCIDRSet: nil,
			},
			other: &EgressCommonRule{
				ToCIDRSet: []CIDRRule{},
			},
			expected: false,
		},
		{
			name: "ToCIDRSet is empty in left operand",
			in: &EgressCommonRule{
				ToCIDRSet: []CIDRRule{},
			},
			other: &EgressCommonRule{
				ToCIDRSet: nil,
			},
			expected: false,
		},
		{
			name: "ToEntities is nil in left operand",
			in: &EgressCommonRule{
				ToEntities: nil,
			},
			other: &EgressCommonRule{
				ToEntities: []Entity{},
			},
			expected: false,
		},
		{
			name: "ToEntities is empty in left operand",
			in: &EgressCommonRule{
				ToEntities: []Entity{},
			},
			other: &EgressCommonRule{
				ToEntities: nil,
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
