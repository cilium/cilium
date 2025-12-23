// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

type fakeEPM struct {
	regen   *set.Set[identity.NumericIdentity]
	fromRev uint64
	toRev   uint64
}

func (m *fakeEPM) UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
	m.regen = idsToRegen
	m.fromRev = fromRev
	m.toRev = toRev

}

type fakeipcache struct {
	waited  bool
	added   set.Set[string]
	removed set.Set[string]
}

func (ipc *fakeipcache) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	ipc.added = set.Set[string]{}
	for _, update := range updates {
		ipc.added.Insert(update.Prefix.String())
	}
	return 2
}
func (ipc *fakeipcache) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	ipc.removed = set.Set[string]{}
	for _, update := range updates {
		ipc.removed.Insert(update.Prefix.String())
	}
	return 2
}
func (ipc *fakeipcache) WaitForRevision(ctx context.Context, rev uint64) error {
	ipc.waited = true
	return nil
}

func TestAddReplaceRemoveRule(t *testing.T) {
	resource := ipcachetypes.ResourceID("resourceid")
	epm := &fakeEPM{}
	ipc := &fakeipcache{}

	ids := identity.IdentityMap{
		100: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "100",
			},
		},
		101: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "101",
			},
		},
		102: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "102",
			},
		},
	}

	pi := &policyImporter{
		log:  slog.Default(),
		repo: policy.NewPolicyRepository(hivetest.Logger(t), ids, nil, nil, nil, testpolicy.NewPolicyMetricsNoop()),
		epm:  epm,
		ipc:  ipc,

		q: make(chan *policytypes.PolicyUpdate, 10),

		prefixesByResource: map[ipcachetypes.ResourceID][]netip.Prefix{},
	}
	pi.repo.GetSubjectSelectorCache().UpdateIdentities(ids, nil, nil)
	pi.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	writeRule := func(r *policyapi.Rule) uint64 {
		t.Helper()

		require.NoError(t, r.Sanitize())

		dc := make(chan uint64, 1)
		pi.processUpdates(context.Background(), []*policytypes.PolicyUpdate{
			{
				Rules:    policyutils.RulesToPolicyEntries([]*policyapi.Rule{r}),
				Resource: resource,
				DoneChan: dc,
			},
		})
		return <-dc
	}

	rev := writeRule(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "100",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToCIDR: policyapi.CIDRSlice{"1.0.1.0/24"},
			}}}))

	// Check that prefix was allocated
	require.True(t, ipc.waited)
	require.ElementsMatch(t, ipc.added.AsSlice(), []string{"1.0.1.0/24"})
	require.Empty(t, ipc.removed.AsSlice())

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{100})

	// Update to new rule that selects id 102 and has two prefixes
	// we should see 1 new prefix, and 2 regenerated endpoints
	rev = writeRule(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "101",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToCIDR: policyapi.CIDRSlice{"1.0.1.0/24", "1.0.2.0/24"},
			}}}))

	require.True(t, ipc.waited)
	// We only allocate 1 new cidr
	require.ElementsMatch(t, ipc.added.AsSlice(), []string{"1.0.2.0/24"})
	require.Empty(t, ipc.removed.AsSlice())

	require.ElementsMatch(t, pi.prefixesByResource[resource], []netip.Prefix{
		netip.MustParsePrefix("1.0.1.0/24"),
		netip.MustParsePrefix("1.0.2.0/24"),
	})

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{100, 101})

	// Swap endpoints and prefixes
	rev = writeRule(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "102",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToCIDR: policyapi.CIDRSlice{"2.0.0.0/24"},
			}}}))

	require.True(t, ipc.waited)
	// We only allocate 1 new cidr
	require.ElementsMatch(t, ipc.removed.AsSlice(), []string{"1.0.1.0/24", "1.0.2.0/24"})
	require.ElementsMatch(t, ipc.added.AsSlice(), []string{"2.0.0.0/24"})

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{101, 102})

}
