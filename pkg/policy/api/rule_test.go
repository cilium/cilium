// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func checkMarshalUnmarshal(t *testing.T, r *Rule) {
	jsonData, err := json.Marshal(r)
	require.NoError(t, err)

	newRule := Rule{}
	err = json.Unmarshal(jsonData, &newRule)
	require.NoError(t, err)

	require.Equal(t, newRule.EndpointSelector.LabelSelector == nil, r.EndpointSelector.LabelSelector == nil)
	require.Equal(t, newRule.NodeSelector.LabelSelector == nil, r.NodeSelector.LabelSelector == nil)
}

// This test ensures that the NodeSelector and EndpointSelector fields are kept
// empty when the rule is marshalled/unmarshalled.
func TestJSONMarshalling(t *testing.T) {
	setUpSuite(t)

	validEndpointRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(t, &validEndpointRule)

	validNodeRule := Rule{
		NodeSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(t, &validNodeRule)
}

func getEgressRuleWithToGroups() *Rule {
	return &Rule{
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToGroups: []Groups{
						GetGroupsRule(),
					},
				},
			},
		},
	}
}

func getEgressDenyRuleWithToGroups() *Rule {
	return &Rule{
		EgressDeny: []EgressDenyRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToGroups: []Groups{
						GetGroupsRule(),
					},
				},
			},
		},
	}
}

func getIngressRuleWithFromGroups() *Rule {
	return &Rule{
		Ingress: []IngressRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromGroups: []Groups{
						GetGroupsRule(),
					},
				},
			},
		},
	}
}

func getIngressDenyRuleWithFromGroups() *Rule {
	return &Rule{
		IngressDeny: []IngressDenyRule{
			{
				IngressCommonRule: IngressCommonRule{
					FromGroups: []Groups{
						GetGroupsRule(),
					},
				},
			},
		},
	}
}

func TestRequiresDerivative(t *testing.T) {
	setUpSuite(t)

	egressWithoutToGroups := Rule{}
	require.False(t, egressWithoutToGroups.RequiresDerivative())

	egressRuleWithToGroups := getEgressRuleWithToGroups()
	require.True(t, egressRuleWithToGroups.RequiresDerivative())

	egressDenyRuleWithToGroups := getEgressDenyRuleWithToGroups()
	require.True(t, egressDenyRuleWithToGroups.RequiresDerivative())

	ingressRuleWithToGroups := getIngressRuleWithFromGroups()
	require.True(t, ingressRuleWithToGroups.RequiresDerivative())

	ingressDenyRuleWithToGroups := getIngressDenyRuleWithFromGroups()
	require.True(t, ingressDenyRuleWithToGroups.RequiresDerivative())
}

func TestCreateDerivative(t *testing.T) {
	setUpSuite(t)

	egressWithoutToGroups := Rule{}
	newRule, err := egressWithoutToGroups.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.Egress)
	require.Empty(t, newRule.EgressDeny)

	RegisterToGroupsProvider(AWSProvider, GetCallBackWithRule("192.168.1.1"))

	egressRuleWithToGroups := getEgressRuleWithToGroups()
	newRule, err = egressRuleWithToGroups.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.EgressDeny)
	require.Len(t, newRule.Egress, 1)
	require.Len(t, newRule.Egress[0].ToCIDRSet, 1)

	egressDenyRuleWithToGroups := getEgressDenyRuleWithToGroups()
	newRule, err = egressDenyRuleWithToGroups.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.Egress)
	require.Len(t, newRule.EgressDeny, 1)
	require.Len(t, newRule.EgressDeny[0].ToCIDRSet, 1)

	ingressRuleWithToGroups := getIngressRuleWithFromGroups()
	newRule, err = ingressRuleWithToGroups.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.IngressDeny)
	require.Len(t, newRule.Ingress, 1)
	require.Len(t, newRule.Ingress[0].FromCIDRSet, 1)

	ingressDenyRuleWithToGroups := getIngressDenyRuleWithFromGroups()
	newRule, err = ingressDenyRuleWithToGroups.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.Ingress)
	require.Len(t, newRule.IngressDeny, 1)
	require.Len(t, newRule.IngressDeny[0].FromCIDRSet, 1)
}
