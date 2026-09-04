// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/compute"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
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
		}.Labels(),
		101: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "101",
			},
		}.Labels(),
		102: labels.LabelArray{
			{
				Source: labels.LabelSourceK8s,
				Key:    "id",
				Value:  "102",
			},
		}.Labels(),
	}

	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo.ID, ids, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())
	polComputer := testcompute.InstantiateCellForTesting(t, logger, "policy-cell", "TestAddReplaceRemoveRule", repo, idmgr)

	pi := &Importer{
		log:      logger,
		repo:     repo,
		computer: polComputer,
		epm:      epm,
		ipc:      ipc,

		q: make(chan *policytypes.PolicyUpdate, 10),

		prefixesByResource: map[ipcachetypes.ResourceID][]netip.Prefix{},
	}
	wg := &sync.WaitGroup{}
	pi.repo.GetSubjectSelectorCache().UpdateIdentities(ids, nil, wg)
	wg.Wait()
	pi.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	writeRules := func(rules ...*policyapi.Rule) uint64 {
		t.Helper()

		for _, r := range rules {
			require.NoError(t, r.ValidateAndSanitize())
		}

		dc := make(chan uint64, 1)
		pi.processUpdates(context.Background(), []*policytypes.PolicyUpdate{
			{
				Rules:    policyutils.RulesToPolicyEntries(rules),
				Resource: resource,
				DoneChan: dc,
			},
		})
		return <-dc
	}

	rev := writeRules(policyapi.NewRule().
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
	rev = writeRules(policyapi.NewRule().
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
	rev = writeRules(policyapi.NewRule().
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

	// Remove all CIDRs
	rev = writeRules(policyapi.NewRule().
		WithEndpointSelector(policyapi.NewESFromK8sLabelSelector("",
			&slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"id": "102",
				},
			}),
		).
		WithEgressRules([]policyapi.EgressRule{{
			EgressCommonRule: policyapi.EgressCommonRule{
				ToEntities: policyapi.EntitySlice{policyapi.EntityHost},
			}}}))

	require.True(t, ipc.waited)

	// We only remove 1 cidr
	require.ElementsMatch(t, ipc.removed.AsSlice(), []string{"2.0.0.0/24"})
	// When no new CIDRs are added the ipc.added value is not updated
	// require.ElementsMatch(t, ipc.added.AsSlice(), []string{})

	// Check that the right endpoints were updated
	require.Equal(t, rev, epm.toRev)
	require.ElementsMatch(t, epm.regen.AsSlice(), []identity.NumericIdentity{102})

	require.ElementsMatch(t, pi.prefixesByResource[resource], []netip.Prefix{})

	rev = writeRules()

	// We removed the rule, so the prefix should no longer be counted
	_, found := pi.prefixesByResource[resource]
	require.False(t, found)
	require.Equal(t, rev, epm.toRev)

}

// fakeComputer records the revision range the importer hands to UpdatePolicy.
type fakeComputer struct {
	compute.PolicyRecomputer
	fromRev, toRev uint64
}

func (c *fakeComputer) UpdatePolicy(_ set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
	c.fromRev, c.toRev = fromRev, toRev
}

// fakeRepo advances the revision by bumpPerReplace on each ReplaceByResource. A
// value above one models the repository advancing by more revisions than the
// import produced, as a BumpRevision from another code path would.
type fakeRepo struct {
	policy.PolicyRepository
	rev            uint64
	bumpPerReplace uint64
}

func (r *fakeRepo) GetRevision() uint64 { return r.rev }

func (r *fakeRepo) ReplaceByResource(policytypes.PolicyEntries, ipcachetypes.ResourceID) (*set.Set[identity.NumericIdentity], uint64, int) {
	r.rev += r.bumpPerReplace
	return &set.Set[identity.NumericIdentity]{}, r.rev, 0
}

// TestImporterCollapsesAdvanceOnOutsideBump checks that the importer advances
// revisions it produced, and when another source bumped the revision during
// the import, collapses the advance range instead of carrying identities
// across a change it did not make.
func TestImporterCollapsesAdvanceOnOutsideBump(t *testing.T) {
	for _, tc := range []struct {
		name           string
		numUpdates     int
		bumpPerReplace uint64
		wantCollapsed  bool
	}{
		{"no outside bump", 1, 1, false},
		{"outside bump", 1, 2, true},
		// A batched import produces more than one revision, so the check must
		// compare against the count it produced, not a hardcoded one.
		{"batched import, no outside bump", 2, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const startRev = 1
			repo := &fakeRepo{rev: startRev, bumpPerReplace: tc.bumpPerReplace}
			comp := &fakeComputer{}
			pi := &Importer{
				log:                hivetest.Logger(t),
				repo:               repo,
				computer:           comp,
				epm:                &fakeEPM{},
				ipc:                &fakeipcache{},
				q:                  make(chan *policytypes.PolicyUpdate, 10),
				prefixesByResource: map[ipcachetypes.ResourceID][]netip.Prefix{},
			}

			updates := make([]*policytypes.PolicyUpdate, tc.numUpdates)
			for i := range updates {
				updates[i] = &policytypes.PolicyUpdate{Resource: ipcachetypes.ResourceID(fmt.Sprintf("res-%d", i))}
			}
			pi.processUpdates(context.Background(), updates)

			endRev := uint64(startRev) + tc.bumpPerReplace*uint64(tc.numUpdates)
			require.Equal(t, endRev, comp.toRev)
			if tc.wantCollapsed {
				require.Equal(t, comp.toRev, comp.fromRev, "advance range should collapse to a no-op")
			} else {
				require.Equal(t, uint64(startRev), comp.fromRev, "advance range should start at the pre-import revision")
			}
		})
	}
}
