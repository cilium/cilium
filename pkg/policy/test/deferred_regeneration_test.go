// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/time"
)

// An endpoint relabeled through ModifyIdentityLabels waits for its new
// identity in StateWaitingForIdentity while it still holds its old one. A
// policy update that arrives then must still reach it once its labels resolve
// back to the old identity, even if it hasn't realized a policy yet.
func TestUpdateWhileWaitingForIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		// failing keeps the endpoint's regenerations failing until the end, so
		// it has not realized a policy when the update arrives.
		failing bool
		// selected is whether the update affects the endpoint's identity.
		selected bool
	}{
		{"realized, unselected update", false, false},
		{"realized, selected update", false, true},
		{"not realized, unselected update", true, false},
		{"not realized, selected update", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRegenFixture(t)
			// Not local yet, so that its first computation is the endpoint's.
			id, _, err := f.allocator.AllocateIdentity(f.ctx, appLabels("a"), true, identity.InvalidIdentity)
			require.NoError(t, err)
			stop := func() {}
			if tc.failing {
				stop = f.computeGate.fail(id.ID)
			}
			defer stop()

			ep := f.addEndpoint(t, appLabels("a"))
			if !tc.failing {
				require.NoError(t, ep.WaitForFirstRegeneration(f.ctx))
			}

			// Relabel, and hold the resolution of the new labels so the
			// endpoint stays waiting for its identity.
			release := f.allocGate.hold("x")
			defer release()
			x := labels.NewLabelsFromModel([]string{"k8s:x=1"})
			require.Eventually(t, func() bool {
				switch ep.GetState() {
				case endpoint.StateReady, endpoint.StateRegenerating:
					require.NoError(t, ep.ModifyIdentityLabels(labels.LabelSourceAny, x, nil, 0))
				}
				return ep.GetState() == endpoint.StateWaitingForIdentity
			}, 10*time.Second, time.Millisecond)

			app := "c"
			if tc.selected {
				app = "a"
			}
			f.importRules(t, "update", selecting(t, "update", app))
			rev := f.repo.GetRevision()
			f.barrier(t)
			require.Equal(t, endpoint.StateWaitingForIdentity, ep.GetState())
			require.Equal(t, !tc.failing, policyRevisionAtLeast(f.ctx, ep, 1, 10*time.Millisecond),
				"endpoint realized a policy")

			// Revert the labels, so they resolve to the endpoint's identity.
			require.NoError(t, ep.ModifyIdentityLabels(labels.LabelSourceAny, nil, x, 0))
			release()
			stop()

			f.requirePolicyCurrent(t)
			require.True(t, policyRevisionAtLeast(f.ctx, ep, rev, 5*time.Second),
				"endpoint did not realize revision %d", rev)
		})
	}
}

func policyRevisionAtLeast(ctx context.Context, ep *endpoint.Endpoint, rev uint64, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-ep.WaitForPolicyRevision(ctx, rev, nil):
		return true
	case <-ctx.Done():
		return false
	}
}
