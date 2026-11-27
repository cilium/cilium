// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/compute"
	testcompute "github.com/cilium/cilium/pkg/testutils/compute"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

// restoreIdentitySuite shares one identity manager between the endpoints, the
// policy repository and the policy computation, as the agent does, so that the
// tests can check that the endpoint identity was registered with the identity
// manager. Unlike setupEndpointSuite() it does not need a kvstore, so the tests
// run as plain unit tests.
type restoreIdentitySuite struct {
	logger  *slog.Logger
	repo    policy.PolicyRepository
	idmgr   identitymanager.IDManager
	fetcher compute.PolicyRecomputer
}

func setupRestoreIdentitySuite(t *testing.T) *restoreIdentitySuite {
	logger := hivetest.Logger(t)
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, ""))

	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())
	fetcher := testcompute.InstantiateCellForTesting(t, logger, "endpoint", "setupRestoreIdentitySuite", repo, idmgr)
	return &restoreIdentitySuite{logger: logger, repo: repo, idmgr: idmgr, fetcher: fetcher}
}

func hostLabels(nodeLabels map[string]string) labels.Labels {
	lbls := labels.NewFrom(labels.LabelHost)
	lbls.MergeLabels(labels.Map2Labels(nodeLabels, labels.LabelSourceK8s))
	return lbls
}

// newRestoringEndpoint returns an endpoint in StateRestoring whose labels and
// security identity were restored from disk, and whose identity has not been
// set yet, as after parseEndpoint().
func newRestoringEndpoint(t *testing.T, s *restoreIdentitySuite, epID uint16, isHost bool, restoredID identity.NumericIdentity, restoredLabels labels.Labels) *Endpoint {
	p := createEndpointParams(t, &fakeendpoint.FakeOrchestrator{}, s.repo, s.fetcher)
	p.IdentityManager = s.idmgr
	model := newTestEndpointModel(int(epID), StateRestoring)
	ep, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)
	ep.Start(uint16(model.ID))
	t.Cleanup(func() {
		ep.Stop()
		ep.controllers.RemoveAllAndWait()
	})

	ep.isHost = isHost
	ep.unconditionalLock()
	ep.replaceIdentityLabels(labels.LabelSourceAny, restoredLabels)
	ep.SecurityIdentity = identity.NewIdentity(restoredID, restoredLabels)
	ep.unlock()
	return ep
}

// blockingRegenerator returns a Regenerator whose regeneration fence has one
// initializer that signals on 'waiting' and then blocks until 'proceed' is
// closed. This emulates a slow regeneration initializer, e.g. the clustermesh
// synchronization, while restoreIdentity() has the endpoint unlocked.
func blockingRegenerator(t *testing.T, waiting chan<- struct{}, proceed <-chan struct{}) *Regenerator {
	logger := hivetest.Logger(t)
	lc := &cell.DefaultLifecycle{}
	fence := regeneration.NewFence(lc, logger)
	fence.Add("blocking-initializer", func(ctx context.Context) error {
		close(waiting)
		select {
		case <-proceed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	require.NoError(t, lc.Start(logger, context.Background()))
	t.Cleanup(func() { require.NoError(t, lc.Stop(logger, context.Background())) })

	return &Regenerator{
		logger:        logger,
		cmWaitFn:      func(context.Context) error { return nil },
		cmWaitTimeout: time.Minute,
		fence:         fence,
	}
}

// restoreIdentityAsync starts restoreIdentity() and waits until it blocks in
// the regeneration fence wait. The returned function unblocks it and returns
// its result.
func restoreIdentityAsync(t *testing.T, ep *Endpoint) func() error {
	t.Helper()
	waiting, proceed := make(chan struct{}), make(chan struct{})
	errCh := make(chan error, 1)
	go func() { errCh <- ep.restoreIdentity(blockingRegenerator(t, waiting, proceed)) }()

	select {
	case <-waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("restoreIdentity did not reach the regeneration fence wait")
	}
	return func() error {
		t.Helper()
		close(proceed)
		select {
		case err := <-errCh:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("restoreIdentity did not return")
			return nil
		}
	}
}

// requireIdentity checks that the endpoint has the given identity and
// identity labels, and that the identity is set and was handed to the
// identity manager, as the regeneration after the restore requires.
func requireIdentity(t *testing.T, s *restoreIdentitySuite, ep *Endpoint, wantID identity.NumericIdentity, wantLabels labels.Labels) {
	t.Helper()
	ep.unconditionalRLock()
	defer ep.runlock()
	require.True(t, ep.identitySet, "identity was not set")
	require.Equal(t, wantID, ep.SecurityIdentity.ID)
	require.True(t, ep.SecurityIdentity.Labels.Equals(wantLabels),
		"security identity labels: got %s, want %s", ep.SecurityIdentity.Labels, wantLabels)
	require.True(t, ep.labels.IdentityLabels().Equals(wantLabels),
		"identity labels: got %s, want %s", ep.labels.IdentityLabels(), wantLabels)

	tracked := false
	for _, m := range s.idmgr.GetIdentityModels() {
		if m.Identity != nil && identity.NumericIdentity(m.Identity.ID) == wantID && m.RefCount > 0 {
			tracked = true
		}
	}
	require.True(t, tracked, "identity is not tracked by the identity manager")
}

// TestRestoreIdentity runs restoreIdentity() on a restored endpoint whose
// labels change, or not, while it waits for the regeneration fence with the
// endpoint unlocked.
func TestRestoreIdentity(t *testing.T) {
	host := identity.ReservedIdentityHost
	stale := hostLabels(map[string]string{"role": "worker"})
	current := hostLabels(map[string]string{"role": "control-plane"})
	// The mock allocator assigns the first global identity, 1000, to the
	// restored pod labels, so no identity change grace period applies.
	podID := identity.NumericIdentity(1000) | identity.IdentityScopeGlobal
	podV1 := labels.Map2Labels(map[string]string{"app": "v1"}, labels.LabelSourceK8s)
	podV2 := labels.Map2Labels(map[string]string{"app": "v2"}, labels.LabelSourceK8s)

	// changeLabels changes the identity labels as UpdateLabels() does, without
	// the identity resolution that follows.
	changeLabels := func(lbls ...labels.Labels) func(*testing.T, *restoreIdentitySuite, *Endpoint) {
		return func(_ *testing.T, _ *restoreIdentitySuite, ep *Endpoint) {
			ep.unconditionalLock()
			for _, l := range lbls {
				ep.replaceIdentityLabels(labels.LabelSourceAny, l)
			}
			ep.unlock()
		}
	}

	for _, tc := range []struct {
		name       string
		isHost     bool
		restoredID identity.NumericIdentity
		restored   labels.Labels
		// securityLabels, if set, replaces the labels of the restored security
		// identity, so that applying the restored identity changes it.
		securityLabels labels.Labels
		duringWait     func(*testing.T, *restoreIdentitySuite, *Endpoint)
		wantID         identity.NumericIdentity
		wantLabels     labels.Labels
	}{
		{
			// Without a concurrent label change the restored identity is applied.
			name: "host, no label change", isHost: true, restoredID: host, restored: stale,
			securityLabels: labels.LabelHost,
			wantID:         host, wantLabels: stale,
		},
		{
			// InitWithNodeLabels() at agent start: the newer identity resolution
			// sets the identity during the wait, and the restore must not revert it.
			name: "host, labels resolved during wait", isHost: true, restoredID: host, restored: stale,
			duringWait: func(t *testing.T, s *restoreIdentitySuite, ep *Endpoint) {
				ep.UpdateLabels(context.Background(), labels.LabelSourceAny, current, current, true)
				requireIdentity(t, s, ep, host, current)
			},
			wantID: host, wantLabels: current,
		},
		{
			// identityLabelsChanged() unlocks the endpoint between the label
			// change and SetIdentity().
			name: "host, resolution in flight", isHost: true, restoredID: host, restored: stale,
			duringWait: changeLabels(current),
			wantID:     host, wantLabels: current,
		},
		{
			// identityLabelsChanged() does not call SetIdentity() when the labels
			// match the identity restored from disk.
			name: "host, labels changed back", isHost: true, restoredID: host, restored: stale,
			duringWait: changeLabels(current, stale),
			wantID:     host, wantLabels: stale,
		},
		{
			// Pod endpoints keep setting the restored identity: their identity
			// resolution is asynchronous, and RegenerateAfterRestore() refreshes
			// their labels from Kubernetes via RunRestoredMetadataResolver().
			name: "pod, labels changed during wait", restoredID: podID, restored: podV1,
			duringWait: changeLabels(podV2),
			wantID:     podID, wantLabels: podV1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setupRestoreIdentitySuite(t)
			epID := uint16(901)
			if tc.isHost {
				epID = 823
			}
			ep := newRestoringEndpoint(t, s, epID, tc.isHost, tc.restoredID, tc.restored)
			if tc.securityLabels != nil {
				ep.unconditionalLock()
				ep.SecurityIdentity = identity.NewIdentity(tc.restoredID, tc.securityLabels)
				ep.unlock()
			}

			finish := restoreIdentityAsync(t, ep)
			if tc.duringWait != nil {
				tc.duringWait(t, s, ep)
			}
			require.NoError(t, finish())
			requireIdentity(t, s, ep, tc.wantID, tc.wantLabels)
		})
	}
}
