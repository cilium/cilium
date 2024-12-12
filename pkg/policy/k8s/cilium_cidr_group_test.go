// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestHasCIDRGroupRef(t *testing.T) {
	testCases := [...]struct {
		name      string
		cnp       *types.SlimCNP
		cidrGroup string
		expected  bool
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
			cidrGroup: "cidr-group-1",
			expected:  false,
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
			cidrGroup: "cidr-group-1",
			expected:  false,
		},
		{
			name: "nil FromCidrSet rule",
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
			cidrGroup: "cidr-group-1",
			expected:  false,
		},
		{
			name: "nil ToCidrSet rule",
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
			cidrGroup: "cidr-group-1",
			expected:  false,
		},
		{
			name: "missing CIDRGroup",
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
											CIDRGroupRef: "cidr-group-3",
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
												CIDRGroupRef: "cidr-group-2",
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
												CIDRGroupRef: "cidr-group-4",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-5",
			expected:  false,
		},
		{
			name: "CIDRGroupRef in Ingress Spec",
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
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
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
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in Egress Spec",
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
						Egress: []api.EgressRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Egress: []api.EgressRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in IngressDeny Spec",
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
					Specs: api.Rules{
						{
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
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in EgressDeny Spec",
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
						EgressDeny: []api.EgressDenyRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							EgressDeny: []api.EgressDenyRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDR in Ingress Spec",
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
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDR in IngressDeny Spec",
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
					Specs: api.Rules{
						{
							IngressDeny: []api.IngressDenyRule{
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
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in IngressDeny Specs",
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
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
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
					},
				},
			},
			cidrGroup: "cidr-group-2",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in Spec (Egress)",
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
						Egress: []api.EgressRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
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
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in Specs (Egress)",
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
						Egress: []api.EgressRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Egress: []api.EgressRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-2",
			expected:  true,
		},
		{
			name: "CIDRGroupRef in IngressDeny Specs",
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
					Specs: api.Rules{
						{
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
					},
				},
			},
			cidrGroup: "cidr-group-2",
			expected:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasCIDRGroupRef(tc.cnp, tc.cidrGroup)
			if got != tc.expected {
				t.Fatalf("expected hasCIDRGroupRef to return %t, got %t", tc.expected, got)
			}
		})
	}
}

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

func TestCIDRGroupRefsToCIDRsSets(t *testing.T) {
	testCases := [...]struct {
		name     string
		refs     []string
		cache    map[string]*cilium_v2_alpha1.CiliumCIDRGroup
		expected map[string][]api.CIDR
		err      string
	}{
		{
			name:     "nil refs",
			refs:     nil,
			cache:    map[string]*cilium_v2_alpha1.CiliumCIDRGroup{},
			expected: map[string][]api.CIDR{},
		},
		{
			name: "missing refs",
			err:  "cidr group \"missing\" not found, skipping translation",
			refs: []string{"missing", "cidr-group-1"},
			cache: map[string]*cilium_v2_alpha1.CiliumCIDRGroup{
				"cidr-group-1": {
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2alpha1",
						Kind:       "CiliumCIDRGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "cidr-group-1",
					},
					Spec: cilium_v2_alpha1.CiliumCIDRGroupSpec{
						ExternalCIDRs: []api.CIDR{api.CIDR("1.1.1.1/32"), api.CIDR("2.2.2.2/32")},
					},
				},
			},
			expected: map[string][]api.CIDR{
				"cidr-group-1": {"1.1.1.1/32", "2.2.2.2/32"},
			},
		},
		{
			name: "with refs",
			refs: []string{"cidr-group-1", "cidr-group-2"},
			cache: map[string]*cilium_v2_alpha1.CiliumCIDRGroup{
				"cidr-group-1": {
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2alpha1",
						Kind:       "CiliumCIDRGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "cidr-group-1",
					},
					Spec: cilium_v2_alpha1.CiliumCIDRGroupSpec{
						ExternalCIDRs: []api.CIDR{api.CIDR("1.1.1.1/32"), api.CIDR("2.2.2.2/32")},
					},
				},
				"cidr-group-2": {
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2alpha1",
						Kind:       "CiliumCIDRGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "cidr-group-2",
					},
					Spec: cilium_v2_alpha1.CiliumCIDRGroupSpec{
						ExternalCIDRs: []api.CIDR{api.CIDR("3.3.3.3/32"), api.CIDR("4.4.4.4/32"), api.CIDR("5.5.5.5/32")},
					},
				},
			},
			expected: map[string][]api.CIDR{
				"cidr-group-1": {"1.1.1.1/32", "2.2.2.2/32"},
				"cidr-group-2": {"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &policyWatcher{cidrGroupCache: tc.cache}
			got, err := p.cidrGroupRefsToCIDRsSets(tc.refs)
			if err != nil && tc.err == "" {
				t.Fatalf("unexpected error from cidrGroupRefsToCIDRsSets: %s", err)
			} else if err != nil && err.Error() != tc.err {
				t.Fatalf("unexpected error divergence from cidrGroupRefsToCIDRsSets: %s != %s", err, tc.err)
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected cidr sets to be %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestCIDRGroupRefsTranslate(t *testing.T) {
	testCases := [...]struct {
		name      string
		cnp       *types.SlimCNP
		cidrsSets map[string][]api.CIDR
		expected  *types.SlimCNP
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
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
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
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
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
		},
		{
			name: "nil FromCidrSet and ToCIDRSet rules",
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
						Ingress: []api.IngressRule{},
						Egress:  []api.EgressRule{},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{},
							Egress:  []api.EgressRule{},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
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
						Ingress: []api.IngressRule{},
						Egress:  []api.EgressRule{},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{},
							Egress:  []api.EgressRule{},
						},
					},
				},
			},
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
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
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
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
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
		},
		{
			name: "with FromCidrSet and ToCIDRSet rules",
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
						Egress: []api.EgressRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1-e",
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
												CIDRGroupRef: "cidr-group-2",
											},
										},
									},
								},
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-3",
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
												CIDRGroupRef: "cidr-group-2-e",
											},
										},
									},
								},
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-3-e",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1":   {"1.1.1.1/32", "2.2.2.2/32"},
				"cidr-group-2":   {"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
				"cidr-group-3":   {},
				"cidr-group-1-e": {"11.11.11.11/32", "12.12.12.12/32"},
				"cidr-group-2-e": {"13.13.13.13/32", "14.14.14.14/32", "15.15.15.15/32"},
				"cidr-group-3-e": {},
			},
			expected: &types.SlimCNP{
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
											Cidr: "1.1.1.1/32",
										},
										{
											Cidr: "2.2.2.2/32",
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
											Cidr: "11.11.11.11/32",
										},
										{
											Cidr: "12.12.12.12/32",
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
												Cidr: "3.3.3.3/32",
											},
											{
												Cidr: "4.4.4.4/32",
											},
											{
												Cidr: "5.5.5.5/32",
											},
										},
									},
								},
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: []api.CIDRRule{}, // Empty list, not nil!
									},
								},
							},
							Egress: []api.EgressRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "13.13.13.13/32",
											},
											{
												Cidr: "14.14.14.14/32",
											},
											{
												Cidr: "15.15.15.15/32",
											},
										},
									},
								},
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: []api.CIDRRule{}, // Empty list, not nil!
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with IngressDeny FromCidrSet rules",
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
					Specs: api.Rules{
						{
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
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-3",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1": {"1.1.1.1/32", "2.2.2.2/32"},
				"cidr-group-2": {"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
				"cidr-group-3": {},
			},
			expected: &types.SlimCNP{
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
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											Cidr: "1.1.1.1/32",
										},
										{
											Cidr: "2.2.2.2/32",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "3.3.3.3/32",
											},
											{
												Cidr: "4.4.4.4/32",
											},
											{
												Cidr: "5.5.5.5/32",
											},
										},
									},
								},
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: []api.CIDRRule{}, // Empty list, not nil!
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with EgressDeny ToCidrSet rules",
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
						EgressDeny: []api.EgressDenyRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							EgressDeny: []api.EgressDenyRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-2",
											},
										},
									},
								},
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
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1": {"1.1.1.1/32", "2.2.2.2/32"},
				"cidr-group-2": {"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
				"cidr-group-3": {},
			},
			expected: &types.SlimCNP{
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
						EgressDeny: []api.EgressDenyRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											Cidr: "1.1.1.1/32",
										},
										{
											Cidr: "2.2.2.2/32",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							EgressDeny: []api.EgressDenyRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "3.3.3.3/32",
											},
											{
												Cidr: "4.4.4.4/32",
											},
											{
												Cidr: "5.5.5.5/32",
											},
										},
									},
								},
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: []api.CIDRRule{}, // Empty list, not nil!
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with mixed FromCidrSet and ToCIDRSet rules",
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
											Cidr: "1.1.1.1/32",
										},
										{
											CIDRGroupRef: "cidr-group-2",
										},
										{
											Cidr: "2.2.2.2/32",
										},
										{
											Cidr: "3.3.3.3/32",
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
											CIDRGroupRef: "cidr-group-1-e",
										},
										{
											Cidr: "11.11.11.11/32",
										},
										{
											CIDRGroupRef: "cidr-group-2-e",
										},
										{
											Cidr: "12.12.12.12/32",
										},
										{
											Cidr: "13.13.13.13/32",
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
												CIDRGroupRef: "cidr-group-3",
											},
											{
												Cidr: "4.4.4.4/32",
											},
										},
									},
								},
							},
						},
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
											{
												Cidr: "5.5.5.5/32",
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
												CIDRGroupRef: "cidr-group-3-e",
											},
											{
												Cidr: "14.14.14.14/32",
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
												CIDRGroupRef: "cidr-group-4-e",
											},
											{
												CIDRGroupRef: "cidr-group-5-e",
											},
											{
												Cidr: "15.15.15.15/32",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1":   {"6.6.6.6/32", "7.7.7.7/32"},
				"cidr-group-2":   {"8.8.8.8/32"},
				"cidr-group-3":   {"9.9.9.9/32", "10.10.10.10/32"},
				"cidr-group-4":   {},
				"cidr-group-5":   {"11.11.11.11/32", "12.12.12.12/32"},
				"cidr-group-1-e": {"16.16.16.16/32", "17.17.17.17/32"},
				"cidr-group-2-e": {"18.18.18.18/32"},
				"cidr-group-3-e": {"19.19.19.19/32", "110.110.110.110/32"},
				"cidr-group-4-e": {},
				"cidr-group-5-e": {"111.111.111.111/32", "112.112.112.112/32"},
			},
			expected: &types.SlimCNP{
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
											Cidr: "1.1.1.1/32",
										},
										{
											Cidr: "2.2.2.2/32",
										},
										{
											Cidr: "3.3.3.3/32",
										},
										{
											Cidr: "6.6.6.6/32",
										},
										{
											Cidr: "7.7.7.7/32",
										},
										{
											Cidr: "8.8.8.8/32",
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
											Cidr: "11.11.11.11/32",
										},
										{
											Cidr: "12.12.12.12/32",
										},
										{
											Cidr: "13.13.13.13/32",
										},
										{
											Cidr: "16.16.16.16/32",
										},
										{
											Cidr: "17.17.17.17/32",
										},
										{
											Cidr: "18.18.18.18/32",
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
												Cidr: "4.4.4.4/32",
											},
											{
												Cidr: "9.9.9.9/32",
											},
											{
												Cidr: "10.10.10.10/32",
											},
										},
									},
								},
							},
						},
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "5.5.5.5/32",
											},
											{
												Cidr: "11.11.11.11/32",
											},
											{
												Cidr: "12.12.12.12/32",
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
												Cidr: "14.14.14.14/32",
											},
											{
												Cidr: "19.19.19.19/32",
											},
											{
												Cidr: "110.110.110.110/32",
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
												Cidr: "15.15.15.15/32",
											},
											{
												Cidr: "111.111.111.111/32",
											},
											{
												Cidr: "112.112.112.112/32",
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
		{
			name: "with mixed IngressDeny FromCidrSet rules",
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
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-1",
										},
										{
											Cidr: "1.1.1.1/32",
										},
										{
											CIDRGroupRef: "cidr-group-2",
										},
										{
											Cidr: "2.2.2.2/32",
										},
										{
											Cidr: "3.3.3.3/32",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-3",
											},
											{
												Cidr: "4.4.4.4/32",
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
												CIDRGroupRef: "cidr-group-4",
											},
											{
												CIDRGroupRef: "cidr-group-5",
											},
											{
												Cidr: "5.5.5.5/32",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1": {"6.6.6.6/32", "7.7.7.7/32"},
				"cidr-group-2": {"8.8.8.8/32"},
				"cidr-group-3": {"9.9.9.9/32", "10.10.10.10/32"},
				"cidr-group-4": {},
				"cidr-group-5": {"11.11.11.11/32", "12.12.12.12/32"},
			},
			expected: &types.SlimCNP{
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
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											Cidr: "1.1.1.1/32",
										},
										{
											Cidr: "2.2.2.2/32",
										},
										{
											Cidr: "3.3.3.3/32",
										},
										{
											Cidr: "6.6.6.6/32",
										},
										{
											Cidr: "7.7.7.7/32",
										},
										{
											Cidr: "8.8.8.8/32",
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												Cidr: "4.4.4.4/32",
											},
											{
												Cidr: "9.9.9.9/32",
											},
											{
												Cidr: "10.10.10.10/32",
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
												Cidr: "5.5.5.5/32",
											},
											{
												Cidr: "11.11.11.11/32",
											},
											{
												Cidr: "12.12.12.12/32",
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
		{
			name: "with Ingress CIDRGroupRef and ExceptCIDRs rules",
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
											ExceptCIDRs:  []api.CIDR{"10.96.0.0/12", "10.112.0.0/12"},
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
											CIDRGroupRef: "cidr-group-1-e",
											ExceptCIDRs:  []api.CIDR{"110.96.0.0/12", "110.112.0.0/12"},
										},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1":   {"10.0.0.0/8"},
				"cidr-group-1-e": {"110.0.0.0/8"},
			},
			expected: &types.SlimCNP{
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
											Cidr:        "10.0.0.0/8",
											ExceptCIDRs: []api.CIDR{"10.96.0.0/12", "10.112.0.0/12"},
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
											Cidr:        "110.0.0.0/8",
											ExceptCIDRs: []api.CIDR{"110.96.0.0/12", "110.112.0.0/12"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			translateCIDRGroupRefs(tc.cnp, tc.cidrsSets)
			if !reflect.DeepEqual(tc.cnp, tc.expected) {
				t.Fatalf("expected translated cnp to be\n%v\n, got\n%v\n", tc.expected, tc.cnp)
			}
		})
	}
}

func TestValidateCIDRRules(t *testing.T) {
	testCases := [...]struct {
		name        string
		cnp         *types.SlimCNP
		shouldError bool
	}{
		{
			name: "nil Spec and Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{},
			},
			shouldError: false,
		},
		{
			name: "Valid CIDR rules",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											Cidr:        api.CIDR("10.0.0.0/8"),
											ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
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
											Cidr:        api.CIDR("10.0.0.0/8"),
											ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
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
											Cidr:        api.CIDR("10.0.0.0/8"),
											ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
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
											Cidr:        api.CIDR("10.0.0.0/8"),
											ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
										},
									},
								},
							},
						},
					},
					Specs: api.Rules{
						&api.Rule{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												Cidr:        api.CIDR("10.0.0.0/8"),
												ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
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
												Cidr:        api.CIDR("10.0.0.0/8"),
												ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
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
												Cidr:        api.CIDR("10.0.0.0/8"),
												ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
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
												Cidr:        api.CIDR("10.0.0.0/8"),
												ExceptCIDRs: []api.CIDR{"10.96.0.0/12"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: false,
		},
		{
			name: "Invalid rule in Ingress Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-test",
											ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in Ingress Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Specs: api.Rules{
						&api.Rule{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-test",
												ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in IngressDeny Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Spec: &api.Rule{
						IngressDeny: []api.IngressDenyRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-test",
											ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in IngressDeny Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Specs: api.Rules{
						&api.Rule{
							IngressDeny: []api.IngressDenyRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-test",
												ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in Egress Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Spec: &api.Rule{
						Egress: []api.EgressRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-test",
											ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in Egress Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Specs: api.Rules{
						&api.Rule{
							Egress: []api.EgressRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-test",
												ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in EgressDeny Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Spec: &api.Rule{
						EgressDeny: []api.EgressDenyRule{
							{
								EgressCommonRule: api.EgressCommonRule{
									ToCIDRSet: api.CIDRRuleSlice{
										{
											CIDRGroupRef: "cidr-group-test",
											ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid rule in EgressDeny Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					Specs: api.Rules{
						&api.Rule{
							EgressDeny: []api.EgressDenyRule{
								{
									EgressCommonRule: api.EgressCommonRule{
										ToCIDRSet: api.CIDRRuleSlice{
											{
												CIDRGroupRef: "cidr-group-test",
												ExceptCIDRs:  []api.CIDR{"10.96.0.0/12"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			shouldError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCIDRRules(tc.cnp)
			if err != nil && !tc.shouldError {
				t.Fatalf("unexpected error while checking CIDRRules in CNP: %s", err)
			}
			if err == nil && tc.shouldError {
				t.Fatal("expected error while checking CIDRRules in CNP, got nil")
			}
		})
	}
}
