// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/u8proto"
)

func kubeAPIServerCachedSelector(td *testData) CachedSelector {
	return td.getCachedSelectorForTest(api.EntitySelectorMapping[api.EntityKubeAPIServer][0])
}

func kubeAPIServerPolicyEntries(rules ...*api.Rule) types.PolicyEntries {
	entries := utils.RulesToPolicyEntries(rules)
	for _, e := range entries {
		e.Subject = labelSelectorA
	}
	return entries
}

func TestEgressToEntitiesKubeAPIServer(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(identity.ListReservedIdentities())

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	cachedSelectorKubeAPIServer := kubeAPIServerCachedSelector(td)

	defaultDenyEgressRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress:           []api.EgressRule{{}},
		Labels:           labelsL3,
	}
	allowKubeAPIServerRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEntities: api.EntitySlice{api.EntityKubeAPIServer},
			},
		}},
		Labels: labelsL3,
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorKubeAPIServer: nil,
			},
			Ingress: false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				cachedSelectorKubeAPIServer: {labelsL3},
			}),
		},
	})

	td.policyMapEquals(t, nil, expected, &defaultDenyEgressRule, &allowKubeAPIServerRule)
}

func TestEgressDenyToEntitiesKubeAPIServer(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
	repo := td.repo

	allowAllEgressRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEntities: api.EntitySlice{api.EntityAll},
			},
		}},
	}
	denyKubeAPIServerRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		EgressDeny: []api.EgressDenyRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEntities: api.EntitySlice{api.EntityKubeAPIServer},
			},
		}},
	}

	repo.mustAdd(allowAllEgressRule)
	repo.mustAdd(denyKubeAPIServerRule)

	flowAToKubeAPIServer := types.Flow{
		From:  idA,
		To:    identity.LookupReservedIdentity(identity.ReservedIdentityKubeAPIServer),
		Proto: u8proto.TCP,
		Dport: 443,
	}

	checkFlow(t, repo, td.identityManager, flowAToKubeAPIServer, false)
	checkFlow(t, repo, td.identityManager, flowAToWorld80, true)
}

func TestEgressToEntitiesKubeAPIServerDuplicatePolicyRemoval(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(identity.ListReservedIdentities())
	logger := hivetest.Logger(t)

	defaultDenyEgressRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress:           []api.EgressRule{{}},
	}
	allowKubeAPIServerRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEntities: api.EntitySlice{api.EntityKubeAPIServer},
			},
		}},
	}

	defaultDenyResource := ipcachetypes.ResourceID("default/default-deny-egress")
	allowResource1 := ipcachetypes.ResourceID("default/to-entities-kube-apiserver")
	allowResource2 := ipcachetypes.ResourceID("default/to-entities-kube-apiserver-2")

	td.addIdentity(idA)
	defer td.removeIdentity(idA)

	td.repo.ReplaceByResource(kubeAPIServerPolicyEntries(&defaultDenyEgressRule), defaultDenyResource)
	td.repo.ReplaceByResource(kubeAPIServerPolicyEntries(&allowKubeAPIServerRule), allowResource1)
	td.repo.ReplaceByResource(kubeAPIServerPolicyEntries(&allowKubeAPIServerRule), allowResource2)

	assertKubeAPIServerEgressAllowed := func() {
		t.Helper()
		td.repo.mutex.RLock()
		defer td.repo.mutex.RUnlock()

		selPolicy, err := td.repo.resolvePolicyLocked(idA)
		require.NoError(t, err)
		defer selPolicy.Detach()

		epPolicy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
		epPolicy.Ready()
		defer epPolicy.Detach(logger)

		_, allowed := epPolicy.allowsIdentity(identity.ReservedIdentityKubeAPIServer)
		require.True(t, allowed, "egress to kube-apiserver should remain allowed")
	}

	assertKubeAPIServerEgressAllowed()

	_, _, numDeleted := td.repo.ReplaceByResource(nil, allowResource1)
	require.Equal(t, 1, numDeleted)

	// Regression coverage for cilium/cilium#17829: deleting one of two
	// equivalent allow policies must not remove kube-apiserver access.
	assertKubeAPIServerEgressAllowed()
}
