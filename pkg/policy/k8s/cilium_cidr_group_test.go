// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestCIDRGroupRefsGet(t *testing.T) {
	testCases := [...]struct {
		name     string
		cnp      *types.SlimCNP
		expected []string
	}{
		{
			name: "nil Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
				},
			},
			expected: nil,
		},
		{
			name: "nil Ingress Spec with non-nil Ingress Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-1",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{"cidr-group-1"},
		},
		{
			name: "nil IngressDeny Spec with non-nil IngressDeny Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Specs: api.Rules{
						{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-1",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{"cidr-group-1"},
		},
		{
			name: "nil Ingress and Egress",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{},
					Specs: api.Rules{
						{},
					},
				},
			},
			expected: nil,
		},
		{
			name: "nil Ingress and IngressDeny FromCidrSet rule",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress:     []api.IngressRule{},
						IngressDeny: []api.IngressDenyRule{},
					},
					Specs: api.Rules{
						{
							Ingress:     []api.IngressRule{},
							IngressDeny: []api.IngressDenyRule{},
						},
					},
				},
			},
			expected: nil,
		},
		{
			name: "nil Egress and EgressDeny ToCidrSet rule",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Egress:     []api.EgressRule{},
						EgressDeny: []api.EgressDenyRule{},
					},
					Specs: api.Rules{
						{
							Egress:     []api.EgressRule{},
							EgressDeny: []api.EgressDenyRule{},
						},
					},
				},
			},
			expected: nil,
		},
		{
			name: "single FromCidrSet rule",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
									},
								},
							},
						},
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-2",
										},
									},
								},
							},
						},
						Egress: []api.EgressRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-3",
										},
									},
								},
							},
						},
						EgressDeny: []api.EgressDenyRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-4",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-5",
											},
										},
									},
								},
							},
						},
						{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-6",
											},
										},
									},
								},
							},
						},
						{
							Egress: []api.EgressRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-7",
											},
										},
									},
								},
							},
						},
						{
							EgressDeny: []api.EgressDenyRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-8",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{
				"cidr-group-1",
				"cidr-group-2",
				"cidr-group-3",
				"cidr-group-4",
				"cidr-group-5",
				"cidr-group-6",
				"cidr-group-7",
				"cidr-group-8",
			},
		},
		{
			name: "single FromCidrSet rule with only CIDR",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
									},
								},
							},
						},
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-2",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "1.1.1.1/32",
											},
										},
									},
								},
							},
						},
						{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "2.2.2.2/32",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{"cidr-group-1", "cidr-group-2"},
		},
		{
			name: "multiple FromCidrSet rules",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
										{
											CIDRGroupRef: "cidr-group-2",
										},
										{
											CIDRGroupRef: "cidr-group-3",
										},
									},
								},
							},
						},
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-6",
										},
										{
											CIDRGroupRef: "cidr-group-7",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-4",
											},
											{
												CIDRGroupRef: "cidr-group-5",
											},
										},
									},
								},
							},
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-8",
											},
											{
												CIDRGroupRef: "cidr-group-9",
											},
											{
												CIDRGroupRef: "cidr-group-10",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{
				"cidr-group-1",
				"cidr-group-2",
				"cidr-group-3",
				"cidr-group-4",
				"cidr-group-5",
				"cidr-group-6",
				"cidr-group-7",
				"cidr-group-8",
				"cidr-group-9",
				"cidr-group-10",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getCIDRGroupRefs(tc.cnp)
			assert.ElementsMatch(t, got, tc.expected)
		})
	}
}
