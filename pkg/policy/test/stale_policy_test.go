// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

// These tests cover the cases in which an endpoint could be left on a selector
// policy that a newer one has replaced, with nothing left to regenerate it.

// An endpoint regeneration that runs while the selector policy of the
// endpoint's identity is being recomputed must install the new selector policy,
// not the one being replaced. This covers an endpoint that gets the identity
// after the recomputation started, by being created or relabeled, and one
// whose regeneration was already queued.
func TestRegenerationDuringPolicyRecomputation(t *testing.T) {
	// Releases the builds held by a case's setup.
	var releaseBuild func()
	for _, tc := range []struct {
		name string
		// setup runs before the recomputation, join after it.
		setup func(t *testing.T, f *regenFixture) *endpoint.Endpoint
		join  func(t *testing.T, f *regenFixture, ep *endpoint.Endpoint) *endpoint.Endpoint
	}{
		{
			name: "endpoint created",
			setup: func(t *testing.T, f *regenFixture) *endpoint.Endpoint {
				return nil
			},
			join: func(t *testing.T, f *regenFixture, _ *endpoint.Endpoint) *endpoint.Endpoint {
				ep := f.templateEP.CopyFromTemplate()
				require.NoError(t, f.epm.AddEndpoint(ep))
				go ep.UpdateLabels(f.ctx, labels.LabelSourceAny, appLabels("a"), nil, true)
				return ep
			},
		},
		{
			name: "endpoint relabeled",
			setup: func(t *testing.T, f *regenFixture) *endpoint.Endpoint {
				return f.createEndpoint(t, appLabels("b"))
			},
			join: func(t *testing.T, f *regenFixture, ep *endpoint.Endpoint) *endpoint.Endpoint {
				ep.UpdateLabels(f.ctx, labels.LabelSourceAny, appLabels("a"), nil, true)
				return ep
			},
		},
		{
			// The update's regeneration of the endpoint is merged into the one
			// already queued.
			name: "regeneration queued",
			setup: func(t *testing.T, f *regenFixture) *endpoint.Endpoint {
				ep := f.createEndpoint(t, appLabels("a"))
				releaseBuild = f.buildGate.hold()
				t.Cleanup(releaseBuild)
				ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
					Reason:            "test",
					RegenerationLevel: regeneration.RegenerateWithoutDatapath,
					ParentContext:     f.ctx,
				})
				return ep
			},
			join: func(t *testing.T, f *regenFixture, ep *endpoint.Endpoint) *endpoint.Endpoint {
				releaseBuild()
				return ep
			},
		},
		{
			name: "endpoint without identity",
			setup: func(t *testing.T, f *regenFixture) *endpoint.Endpoint {
				ep := f.templateEP.CopyFromTemplate()
				require.NoError(t, f.epm.AddEndpoint(ep))
				return ep
			},
			join: func(t *testing.T, f *regenFixture, ep *endpoint.Endpoint) *endpoint.Endpoint {
				ep.UpdateLabels(f.ctx, labels.LabelSourceAny, appLabels("a"), nil, true)
				return ep
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegenFixture(t)
			idA := f.localIdentity(t, appLabels("a"))
			old, _, _, _ := f.computer.GetIdentityPolicyByIdentity(idA)

			ep := tc.setup(t, f)

			// Hold the recomputation of the identity's selector policy, so the
			// committed one is the one being replaced.
			release := f.computeGate.hold(idA.ID)
			defer release()
			policy.NewUpdater(hivetest.Logger(t), f.repo, f.computer, f.epm).TriggerPolicyUpdates("test")

			before := f.fetcher.fetches(idA.ID)
			ep = tc.join(t, f, ep)
			// Once the endpoint's regeneration has fetched the identity's
			// policy, give it the chance to realize the policy being replaced.
			require.Eventually(t, func() bool { return f.fetcher.fetches(idA.ID) > before }, 5*time.Second, time.Millisecond)
			_ = testutils.WaitUntilWithSleep(func() bool {
				p := ep.GetDesiredPolicy()
				return p != nil && policy.SelectorPolicy(p.SelectorPolicy) == old.NewPolicy
			}, 50*time.Millisecond, time.Millisecond)
			release()

			f.requirePolicyCurrent(t)
		})
	}
}

// An endpoint that has yet to realize a policy, and whose identity an update
// didn't affect, must not cause the identity's policy to be replaced, as the
// update doesn't regenerate the identity's other endpoints.
func TestInitializingEndpointUnaffectedUpdate(t *testing.T) {
	f := newRegenFixture(t)
	f.createEndpoint(t, appLabels("a"))

	// Keep the second endpoint from completing its first regeneration, so it
	// is initializing when the update arrives.
	release := f.buildGate.hold()
	defer release()
	f.addEndpoint(t, appLabels("a"))

	f.importSelecting(t, "select-c", "c")
	// Give a recomputation the update may have queued the chance to commit.
	time.Sleep(100 * time.Millisecond)
	release()

	f.requirePolicyCurrent(t)
}

// A regeneration that fails because the identity's policy computation keeps
// failing is retried. The retry must not realize the policy being replaced.
func TestPolicyComputationFailureRetry(t *testing.T) {
	f := newRegenFixture(t)
	ep := f.createEndpoint(t, appLabels("a"))
	id, err := ep.GetSecurityIdentity()
	require.NoError(t, err)

	before := f.fetcher.fetches(id.ID)
	stop := f.computeGate.fail(id.ID)
	defer stop()
	f.importRules(t, "select-a", selecting(t, "select-a", "a"))
	// Wait for the regeneration to fail on the computation and be retried
	// while the computation still fails.
	require.Eventually(t, func() bool { return f.fetcher.fetches(id.ID) >= before+2 }, 10*time.Second, time.Millisecond)
	stop()

	f.requirePolicyCurrent(t)
}

// Replacing a selector policy must not regenerate the endpoints still on it,
// since the update that replaced it regenerates them already.
func TestSupersedeDoesNotRegenerateEndpoints(t *testing.T) {
	regenerations := newRegenerationCounter(t)
	f := newRegenFixture(t)

	for _, app := range []string{"a", "b"} {
		for range 10 {
			f.createEndpoint(t, appLabels(app))
		}
	}
	settleRegenerations(t, f.ctx, f.epm, regenerations)
	before := regenerationsByReason(regenerations)

	for _, name := range []string{"p1", "p2", "p3"} {
		f.importSelecting(t, name+"-a", "a")
		f.importSelecting(t, name+"-b", "b")
	}
	settleRegenerations(t, f.ctx, f.epm, regenerations)
	after := regenerationsByReason(regenerations)

	require.Zero(t, after[regeneration.ReasonSelectorPolicyStale]-before[regeneration.ReasonSelectorPolicyStale])
	require.GreaterOrEqual(t, after[regeneration.ReasonPolicyUpdate]-before[regeneration.ReasonPolicyUpdate], uint64(60))
}
