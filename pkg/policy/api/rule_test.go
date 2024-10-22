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
	require.Nil(t, err)

	newRule := Rule{}
	err = json.Unmarshal(jsonData, &newRule)
	require.Nil(t, err)

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
	require.Equal(t, false, egressWithoutToGroups.RequiresDerivative())

	egressRuleWithToGroups := getEgressRuleWithToGroups()
	require.Equal(t, true, egressRuleWithToGroups.RequiresDerivative())

	egressDenyRuleWithToGroups := getEgressDenyRuleWithToGroups()
	require.Equal(t, true, egressDenyRuleWithToGroups.RequiresDerivative())

	ingressRuleWithToGroups := getIngressRuleWithFromGroups()
	require.Equal(t, true, ingressRuleWithToGroups.RequiresDerivative())

	ingressDenyRuleWithToGroups := getIngressDenyRuleWithFromGroups()
	require.Equal(t, true, ingressDenyRuleWithToGroups.RequiresDerivative())
}

func TestCreateDerivative(t *testing.T) {
	setUpSuite(t)

	egressWithoutToGroups := Rule{}
	newRule, err := egressWithoutToGroups.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.Egress))
	require.Equal(t, 0, len(newRule.EgressDeny))

	RegisterToGroupsProvider(AWSProvider, GetCallBackWithRule("192.168.1.1"))

	egressRuleWithToGroups := getEgressRuleWithToGroups()
	newRule, err = egressRuleWithToGroups.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.EgressDeny))
	require.Equal(t, 1, len(newRule.Egress))
	require.Equal(t, 1, len(newRule.Egress[0].ToCIDRSet))

	egressDenyRuleWithToGroups := getEgressDenyRuleWithToGroups()
	newRule, err = egressDenyRuleWithToGroups.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.Egress))
	require.Equal(t, 1, len(newRule.EgressDeny))
	require.Equal(t, 1, len(newRule.EgressDeny[0].ToCIDRSet))

	ingressRuleWithToGroups := getIngressRuleWithFromGroups()
	newRule, err = ingressRuleWithToGroups.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.IngressDeny))
	require.Equal(t, 1, len(newRule.Ingress))
	require.Equal(t, 1, len(newRule.Ingress[0].FromCIDRSet))

	ingressDenyRuleWithToGroups := getIngressDenyRuleWithFromGroups()
	newRule, err = ingressDenyRuleWithToGroups.CreateDerivative(context.TODO())
	require.Nil(t, err)
	require.Equal(t, 0, len(newRule.Ingress))
	require.Equal(t, 1, len(newRule.IngressDeny))
	require.Equal(t, 1, len(newRule.IngressDeny[0].FromCIDRSet))
}
