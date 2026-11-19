// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

// The first time an endpoint is regenerated, policy is computed for it before
// the endpoint waits for a build permit. Unless policy changed in the
// meantime, the regeneration must not fetch and distill the policy again.
func TestFirstRegenerationFetchesPolicyOnce(t *testing.T) {
	for _, importing := range []bool{false, true} {
		t.Run(fmt.Sprintf("importing=%t", importing), func(t *testing.T) {
			f := newRegenFixture(t)
			id := f.localIdentity(t, appLabels("b"))

			release := f.buildGate.hold()
			defer release()
			ep := f.addEndpoint(t, appLabels("b"))
			// The initial policy computation fetches the policy.
			require.Eventually(t, func() bool { return f.fetcher.fetches(id.ID) > 0 }, 5*time.Second, time.Millisecond)

			var hold chan uint64
			if importing {
				// Hold an import after it bumped the revision and before it
				// queued the work for it.
				hold = make(chan uint64)
				startRev := f.repo.GetRevision()
				f.importer.UpdatePolicy(policyUpdate("select-a", selecting(t, "select-a", "a"), hold))
				require.Eventually(t, func() bool { return f.repo.GetRevision() > startRev }, 5*time.Second, time.Millisecond)
			}

			before := f.fetcher.fetches(id.ID)
			release()
			require.NoError(t, ep.WaitForFirstRegeneration(f.ctx))
			require.Zero(t, f.fetcher.fetches(id.ID)-before, "first regeneration fetched the policy again")
			if importing {
				start := time.Now()
				require.True(t, f.regenerate(ep), "regeneration failed")
				require.Less(t, time.Since(start), 500*time.Millisecond, "regeneration waited for the import")
				f.receive(t, hold)
				f.barrier(t)
				f.requirePolicyCurrent(t)
			}
		})
	}
}
