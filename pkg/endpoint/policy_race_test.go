// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

// TestPreviousMapStateSizesRace checks that PreviousMapStateSizes, which policy computation
// calls with the endpoint unlocked, does not race with the incremental map changes
// ApplyPolicyMapChanges applies to the endpoint's current desired policy. The named port in
// the rule below makes the desired policy's map state maintain the identity index that both
// sides touch. Run with -race.
func TestPreviousMapStateSizesRace(t *testing.T) {
	pe := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled("always")
	defer policy.SetPolicyEnabled(pe)

	logger := hivetest.Logger(t)
	fakeAllocator := testidentity.NewMockIdentityAllocator(nil)
	idManager := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo.ID, fakeAllocator.GetIdentityCache(), nil, nil, idManager, testpolicy.NewPolicyMetricsNoop())
	polComputer := testcompute.InstantiateCellForTesting(t, logger, "endpoint-policy_race_test", t.Name(), repo, idManager)

	addIdentity := func(labelKeys ...string) *identity.Identity {
		lbls := labels.Labels{}
		for _, labelKey := range labelKeys {
			lbls[labelKey] = labels.NewLabel("k8s:"+labelKey, "", "")
		}
		id, _, err := fakeAllocator.AllocateIdentity(context.Background(), lbls, false, 0)
		assert.NoError(t, err)
		wg := &sync.WaitGroup{}
		repo.GetSelectorCache().UpdateIdentities(identity.IdentityMap{
			id.ID: id.LabelArray,
		}, nil, wg)
		wg.Wait()
		return id
	}

	podID := addIdentity("pod")
	idManager.Add(podID)

	ep := Endpoint{
		policyRepo:       repo,
		policyFetcher:    polComputer,
		desiredPolicy:    policy.NewEndpointPolicy(logger, repo),
		labels:           labels.NewOpLabels(),
		SecurityIdentity: podID,
		identityManager:  idManager,
		status:           NewEndpointStatus(),
	}
	ep.UpdateLogger(nil)

	// Deny egress from the pod to all 'peer' identities. The named port makes the computed
	// policy maintain the map state identity index.
	egressDenyRule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("pod")),
		EgressDeny: []api.EgressDenyRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("peer")),
				},
			},
			ToPorts: []api.PortDenyRule{{
				Ports: []api.PortProtocol{
					{Port: "80", Protocol: "TCP"},
					{Port: "http-alt", Protocol: "TCP"},
				},
			}},
		}},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, "egressDenyRule", labels.LabelSourceAny),
		},
	}
	_, rev := repo.MustAddList(api.Rules{egressDenyRule})
	computePolicyForEPAndWait(t, &ep, polComputer, rev)

	stats := new(regenerationStatistics)
	datapathRegenCtxt := new(datapathRegenerationContext)
	datapathRegenCtxt.policyRevisionToWaitFor = rev
	require.NoError(t, ep.regeneratePolicy(stats, datapathRegenCtxt))
	require.NoError(t, ep.lockAlive())
	err := ep.setDesiredPolicy(datapathRegenCtxt)
	ep.unlock()
	require.NoError(t, err)
	require.True(t, ep.desiredPolicy.IsValid())

	const numIdentities = 256

	var wg sync.WaitGroup
	wg.Add(2)
	done := make(chan struct{})

	// Writer: allocate identities selected by the rule and apply the resulting incremental
	// map changes to the desired policy while holding the endpoint lock.
	go func() {
		defer wg.Done()
		defer close(done)
		cmp := completion.NewWaitGroup(context.Background())
		for i := range numIdentities {
			addIdentity("peer", fmt.Sprintf("peer%d", i))
			err, _, finalizeFunc := ep.ApplyPolicyMapChanges(cmp)
			if !assert.NoError(t, err) {
				return
			}
			if finalizeFunc != nil {
				finalizeFunc()
			}
		}
	}()

	// Reader: policy recomputation sizes the new map state after the current one with the
	// endpoint unlocked.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				ep.PreviousMapStateSizes()
			}
		}
	}()

	wg.Wait()

	// All the identity additions must have been applied to the desired policy.
	require.GreaterOrEqual(t, ep.desiredPolicy.Len(), numIdentities)
}

// PreviousMapStateSizes must return zero sizes when the endpoint has no computed policy.
func TestPreviousMapStateSizesNilPolicy(t *testing.T) {
	require.Equal(t, policy.MapStateSizes{}, (&Endpoint{}).PreviousMapStateSizes())
}
