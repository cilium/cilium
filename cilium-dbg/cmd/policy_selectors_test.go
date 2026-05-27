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

	got := getTopPolicySelectorIdentityCounts(resp, 2, 0)

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

	got := getTopPolicySelectorIdentityCounts(resp, 0, 1)

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

func testPolicySelectorIdentities(count int) []int64 {
	identities := make([]int64, count)
	for i := range identities {
		identities[i] = int64(i + 1)
	}
	return identities
}
