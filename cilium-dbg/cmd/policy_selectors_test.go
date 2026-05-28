// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	labelpkg "github.com/cilium/cilium/pkg/labels"
)

func TestGetTopPolicySelectorIdentityCounts(t *testing.T) {
	resp := models.SelectorCache{
		{
			Selector:   "selector-a",
			Identities: testPolicySelectorIdentities(10),
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "selector-b",
			Identities: testPolicySelectorIdentities(5),
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "selector-c",
			Identities: testPolicySelectorIdentities(12),
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-b", "uid-b", "CiliumNetworkPolicy"),
				testPolicySelectorLabels("", "policy-c", "uid-c", "CiliumClusterwideNetworkPolicy"),
			},
		},
		{
			Selector:   "selector-d",
			Identities: testPolicySelectorIdentities(11),
		},
		{
			Selector:   "selector-e",
			Identities: testPolicySelectorIdentities(1),
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-e", "uid-e", "CiliumNetworkPolicy"),
			},
		},
	}

	got := getTopPolicySelectorIdentityCounts(resp, 2, 0, false)

	require.Equal(t, []policySelectorIdentityCount{
		{
			IdentityCount: 12,
			Policy:        "policy-c",
			DerivedFrom:   "CiliumClusterwideNetworkPolicy",
			UID:           "uid-c",
		},
		{
			IdentityCount: 12,
			Policy:        "policy-b",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-b",
		},
		{
			IdentityCount: 11,
		},
		{
			IdentityCount: 10,
			Policy:        "policy-a",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-a",
		},
	}, got)
}

func TestGetTopPolicySelectorIdentityCountsAppliesLimit(t *testing.T) {
	resp := models.SelectorCache{
		{
			Identities: testPolicySelectorIdentities(3),
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Identities: testPolicySelectorIdentities(2),
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-b", "uid-b", "CiliumNetworkPolicy"),
			},
		},
	}

	got := getTopPolicySelectorIdentityCounts(resp, 0, 1, false)

	require.Equal(t, []policySelectorIdentityCount{
		{
			IdentityCount: 3,
			Policy:        "policy-a",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-a",
		},
	}, got)
}

func TestGetTopPolicySelectorIdentityCountsWithDirection(t *testing.T) {
	resp := models.SelectorCache{
		{
			Selector:   "selector-a",
			Identities: []int64{1, 2, 3},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("egress", "default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "selector-b",
			Identities: []int64{3, 4},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("ingress", "default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "selector-c",
			Identities: []int64{10},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("egress", "default", "policy-b", "uid-b", "CiliumNetworkPolicy"),
			},
		},
	}

	got := getTopPolicySelectorIdentityCounts(resp, 2, 0, false)

	require.Equal(t, []policySelectorIdentityCount{
		{
			IdentityCount: 5,
			Policy:        "policy-a",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-a",
		},
	}, got)

	got = getTopPolicySelectorIdentityCounts(resp, 0, 0, true)

	require.Equal(t, []policySelectorIdentityCount{
		{
			IdentityCount: 3,
			Direction:     "egress",
			Policy:        "policy-a",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-a",
		},
		{
			IdentityCount: 2,
			Direction:     "ingress",
			Policy:        "policy-a",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-a",
		},
		{
			IdentityCount: 1,
			Direction:     "egress",
			Policy:        "policy-b",
			Namespace:     "default",
			DerivedFrom:   "CiliumNetworkPolicy",
			UID:           "uid-b",
		},
	}, got)
}

func TestGetTopPolicySelectorEndpointIdentityCounts(t *testing.T) {
	policySelectors := models.SelectorCache{
		{
			Selector:   "remote-selector-a",
			Identities: []int64{1, 2, 3},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "remote-selector-b",
			Identities: []int64{3, 4},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "remote-selector-c",
			Identities: []int64{10, 11},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-b", "uid-b", "CiliumNetworkPolicy"),
			},
		},
	}
	subjectSelectors := models.SelectorCache{
		{
			Selector:   "subject-selector-a",
			Identities: []int64{100, 101},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Selector:   "subject-selector-b",
			Identities: []int64{100},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-b", "uid-b", "CiliumNetworkPolicy"),
			},
		},
	}
	endpoints := []*models.Endpoint{
		testPolicySelectorEndpoint(10, 100, "fd00::10", "10.0.0.10", []string{"k8s:app=frontend"}),
		testPolicySelectorEndpoint(11, 101, "fd00::11", "10.0.0.11", []string{"k8s:app=backend"}),
		testPolicySelectorEndpoint(12, 102, "fd00::12", "10.0.0.12", []string{"k8s:app=unused"}),
	}

	got := getTopPolicySelectorEndpointIdentityCounts(policySelectors, subjectSelectors, endpoints, 0, 0, false)

	require.Equal(t, []policySelectorEndpointIdentityCount{
		{
			IdentityCount:    6,
			EndpointID:       10,
			EndpointIdentity: 100,
			IPv6:             "fd00::10",
			IPv4:             "10.0.0.10",
			Labels:           []string{"k8s:app=frontend"},
		},
		{
			IdentityCount:    4,
			EndpointID:       11,
			EndpointIdentity: 101,
			IPv6:             "fd00::11",
			IPv4:             "10.0.0.11",
			Labels:           []string{"k8s:app=backend"},
		},
	}, got)
}

func TestGetTopPolicySelectorEndpointIdentityCountsAppliesThresholdAndLimit(t *testing.T) {
	policySelectors := models.SelectorCache{
		{
			Identities: []int64{1, 2, 3},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
	}
	subjectSelectors := models.SelectorCache{
		{
			Identities: []int64{100, 101},
			Labels: models.LabelArrayList{
				testPolicySelectorLabels("default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
	}
	endpoints := []*models.Endpoint{
		testPolicySelectorEndpoint(10, 100, "fd00::10", "10.0.0.10", nil),
		testPolicySelectorEndpoint(11, 101, "fd00::11", "10.0.0.11", nil),
	}

	got := getTopPolicySelectorEndpointIdentityCounts(policySelectors, subjectSelectors, endpoints, 3, 1, false)

	require.Equal(t, []policySelectorEndpointIdentityCount{
		{
			IdentityCount:    3,
			EndpointID:       10,
			EndpointIdentity: 100,
			IPv6:             "fd00::10",
			IPv4:             "10.0.0.10",
			Labels:           []string{},
		},
	}, got)
}

func TestGetTopPolicySelectorEndpointIdentityCountsWithDirection(t *testing.T) {
	policySelectors := models.SelectorCache{
		{
			Identities: []int64{1, 2, 3},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("egress", "default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Identities: []int64{3, 4},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("ingress", "default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
	}
	subjectSelectors := models.SelectorCache{
		{
			Identities: []int64{100},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("egress", "default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
		{
			Identities: []int64{100},
			Origins: []*models.SelectorIdentityMappingOrigin{
				testPolicySelectorOrigin("ingress", "default", "policy-a", "uid-a", "CiliumNetworkPolicy"),
			},
		},
	}
	endpoints := []*models.Endpoint{
		testPolicySelectorEndpoint(10, 100, "fd00::10", "10.0.0.10", nil),
	}
	ingressIdentityCount := 2
	egressIdentityCount := 3

	got := getTopPolicySelectorEndpointIdentityCounts(policySelectors, subjectSelectors, endpoints, 0, 0, true)

	require.Equal(t, []policySelectorEndpointIdentityCount{
		{
			IdentityCount:        5,
			IngressIdentityCount: &ingressIdentityCount,
			EgressIdentityCount:  &egressIdentityCount,
			EndpointID:           10,
			EndpointIdentity:     100,
			IPv6:                 "fd00::10",
			IPv4:                 "10.0.0.10",
			Labels:               []string{},
		},
	}, got)
}

func testPolicySelectorLabels(namespace, name, uid, derivedFrom string) models.LabelArray {
	lbls := models.LabelArray{
		{
			Key:    k8sconst.PolicyLabelDerivedFrom,
			Source: labelpkg.LabelSourceK8s,
			Value:  derivedFrom,
		},
		{
			Key:    k8sconst.PolicyLabelName,
			Source: labelpkg.LabelSourceK8s,
			Value:  name,
		},
		{
			Key:    k8sconst.PolicyLabelUID,
			Source: labelpkg.LabelSourceK8s,
			Value:  uid,
		},
	}

	if namespace != "" {
		lbls = append(lbls, &models.Label{
			Key:    k8sconst.PolicyLabelNamespace,
			Source: labelpkg.LabelSourceK8s,
			Value:  namespace,
		})
	}

	return lbls
}

func testPolicySelectorOrigin(direction, namespace, name, uid, derivedFrom string) *models.SelectorIdentityMappingOrigin {
	return &models.SelectorIdentityMappingOrigin{
		Direction: direction,
		Labels:    testPolicySelectorLabels(namespace, name, uid, derivedFrom),
	}
}

func testPolicySelectorEndpoint(id, identity int64, ipv6, ipv4 string, lbls []string) *models.Endpoint {
	return &models.Endpoint{
		ID: id,
		Status: &models.EndpointStatus{
			Identity: &models.Identity{ID: identity},
			Labels: &models.LabelConfigurationStatus{
				SecurityRelevant: lbls,
			},
			Networking: &models.EndpointNetworking{
				Addressing: []*models.AddressPair{
					{
						IPv6: ipv6,
						IPv4: ipv4,
					},
				},
			},
		},
	}
}

func testPolicySelectorIdentities(count int) []int64 {
	identities := make([]int64, count)
	for i := range identities {
		identities[i] = int64(i + 1)
	}
	return identities
}
