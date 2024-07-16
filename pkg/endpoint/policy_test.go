// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestUpdateVisibilityPolicy(t *testing.T) {
	setupEndpointSuite(t)
	do := &DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil, nil)}
	ep := NewTestEndpointWithState(t, do, do, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)
	ep.UpdateVisibilityPolicy(func(_, _ string) (string, error) {
		return "", nil
	})
	require.Nil(t, ep.visibilityPolicy)

	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return "<Ingress/80/TCP/HTTP>", nil
	})

	require.NotEqual(t, nil, ep.visibilityPolicy)
	require.Equal(t, &policy.VisibilityMetadata{
		Parser:  policy.ParserTypeHTTP,
		Port:    uint16(80),
		Proto:   u8proto.TCP,
		Ingress: true,
	}, ep.visibilityPolicy.Ingress["80/TCP"])

	// Check that updating after previously having value works.
	ep.UpdateVisibilityPolicy(func(_, _ string) (string, error) {
		return "", nil
	})
	require.Nil(t, ep.visibilityPolicy)
}

// This test fuzzes the incremental update engine from an end-to-end perspective
// to ensure we don't ever miss an incremental update.
//
// It works by simulating a "churning" IPcache that is constantly allocating new identities.
// There is a single policy that -- funnily enough -- selects all of the new identities.
// We then continuously simulate endpoint regeneration and ensure the computed policy contains
// all the generated identities.
//
// By default, we test 1000 identities, which should take less than 10 seconds. If this test fails,
// please bump the factor to something massive and start debugging :-).
func TestIncrementalUpdatesDuringPolicyGeneration(t *testing.T) {
	const testfactor = 1000 // bump this to stress-test

	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	idcache := make(identity.IdentityMap, testfactor)
	fakeAllocator := testidentity.NewMockIdentityAllocator(idcache)
	repo := policy.NewPolicyRepository(fakeAllocator.GetIdentityCache(), nil, nil, nil)

	defer func() {
		repo.RepositoryChangeQueue.Stop()
		repo.RuleReactionQueue.Stop()
		repo.RepositoryChangeQueue.WaitToBeDrained()
		repo.RuleReactionQueue.WaitToBeDrained()
	}()

	addIdentity := func(labelKeys ...string) *identity.Identity {
		t.Helper()
		lbls := labels.Labels{}
		for _, labelKey := range labelKeys {
			lbls[labelKey] = labels.NewLabel("k8s:"+labelKey, "", "")
		}
		id, _, err := fakeAllocator.AllocateIdentity(context.Background(), lbls, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		// t.Logf("allocated label %s id %d", labelKeys, id.ID) // commented out for speed

		wg := &sync.WaitGroup{}
		repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{
			id.ID: id.LabelArray,
		}, nil, wg)
		wg.Wait()
		return id
	}

	podID := addIdentity("pod")
	repo.GetPolicyCache().LocalEndpointIdentityAdded(podID)

	ep := Endpoint{
		SecurityIdentity: podID,
		policyGetter:     &mockPolicyGetter{repo},
	}
	ep.UpdateLogger(nil)

	podSelectLabel := labels.ParseSelectLabel("pod")
	egressSelectLabel := labels.ParseSelectLabel("peer")

	// Create a rule for our pod that selects all peer identities
	egressDenyRule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(podSelectLabel),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(egressSelectLabel),
					},
				},
				ToPorts: []api.PortDenyRule{
					{
						Ports: []api.PortProtocol{
							{
								Port:     "80",
								Protocol: "TCP",
							},
						},
					},
				},
			},
		},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, "egressDenyRule", labels.LabelSourceAny),
		},
	}

	repo.MustAddList(api.Rules{egressDenyRule})

	// Track all IDs we allocate so we can validate later that we never miss any
	checkMutex := lock.Mutex{}
	allocatedIDs := make(sets.Set[identity.NumericIdentity], testfactor)
	done := false

	// simulate ipcache churn: continuously allocate IDs and push them to the policy engine.
	go func() {
		for i := 0; i < testfactor; i++ {
			if i%100 == 0 {
				t.Log(i)
			}
			id := addIdentity("peer", fmt.Sprintf("peer%d", i))

			// note: we could stop checking here and the last ID would be missing from allocatedIDs
			// so we will have to handle the case where we select one more ID than is in allocatedIDs
			checkMutex.Lock()
			allocatedIDs.Insert(id.ID)
			checkMutex.Unlock()

		}
		done = true
	}()

	stats := new(regenerationStatistics)
	// Continuously compute policy for the pod and ensure we never missed an incremental update.
	for {
		t.Log("Calculating policy...")
		res, err := ep.regeneratePolicy(stats)
		assert.Nil(t, err)

		// Sleep a random amount, so we accumulate some changes
		// This does not slow down the test, since we always generate testFactor identities.
		time.Sleep(time.Duration(rand.IntN(10)) * time.Millisecond)

		// Now, check that all the expected entries are there
		checkMutex.Lock()
		t.Log("Checking policy...")

		// Apply any pending incremental changes
		// This mirrors the existing code, where we consume map changes
		// while holding the endpoint lock
		res.endpointPolicy.ConsumeMapChanges()
		haveIDs := make(sets.Set[identity.NumericIdentity], testfactor)
		res.endpointPolicy.GetPolicyMap().ForEach(func(k policy.Key, _ policy.MapStateEntry) bool {
			haveIDs.Insert(identity.NumericIdentity(k.Identity))
			return true
		})

		// It is okay if we have *more* IDs than allocatedIDs, since we may have propagated
		// an ID change through the policy system but not yet added to the extra list we're
		// keeping in this test.
		//
		// It is confusing, but this assertion checks that allocatedIDs is a subset of haveIDs,
		// not the other way around.
		assert.Subset(t, haveIDs, allocatedIDs, "stress-testing the incremental update system failed! DO NOT just retest, there is a race condition!")

		checkMutex.Unlock()

		if done {
			break
		}
	}
}

type mockPolicyGetter struct {
	repo *policy.Repository
}

func (m *mockPolicyGetter) GetPolicyRepository() *policy.Repository {
	return m.repo
}
