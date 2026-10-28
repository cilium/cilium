// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/time"
)

// Another path bumping the revision during an import recomputes all identities
// at its revision. The import must still make the policies of the identities it
// didn't affect current at its own revision, which regenerations wait for.
func TestRevisionBumpDuringImport(t *testing.T) {
	f := newRegenFixture(t)
	ep := f.createEndpoint(t, appLabels("b"))

	// Both updates are processed in one import. The first one's done channel
	// is unbuffered, which holds the import between the two.
	hold := make(chan uint64)
	done := make(chan uint64, 1)
	startRev := f.repo.GetRevision()
	f.importer.UpdatePolicy(policyUpdate("select-a", selecting(t, "select-a", "a"), hold))
	f.importer.UpdatePolicy(policyUpdate("select-c", selecting(t, "select-c", "c"), done))
	require.Eventually(t, func() bool { return f.repo.GetRevision() > startRev }, 5*time.Second, time.Millisecond)

	// Bump the revision like TriggerPolicyUpdates does, but wait for the
	// recomputation, so that it completes before the import's last revision.
	rev := f.repo.BumpRevision()
	ws, err := f.computer.RecomputeIdentityPolicyForAllIdentities(rev)
	require.NoError(t, err)
	_, err = ws.Wait(f.ctx, 0)
	require.NoError(t, err)
	f.epm.RegenerateAllForPolicy(rev)

	require.Equal(t, startRev+1, f.receive(t, hold))
	require.Equal(t, rev+1, f.receive(t, done))
	f.barrier(t)

	require.True(t, f.regenerate(ep), "regeneration failed")
	f.requirePolicyCurrent(t)
}

// A regeneration waits for the policy revision requested when it was triggered.
// A policy update that arrives before the regeneration starts, and doesn't
// affect the endpoint's identity, must not make it wait for the computations
// running for other updates.
func TestRegenerationWaitsForTriggerRevision(t *testing.T) {
	f := newRegenFixture(t)
	ep := f.createEndpoint(t, appLabels("b"))
	idB, err := ep.GetSecurityIdentity()
	require.NoError(t, err)
	idA := f.localIdentity(t, appLabels("a"))

	// An import whose computation of a is held, so the policy computer is busy
	// with it. The import's advance carries b, as it is in the same batch.
	releaseCompute := f.computeGate.hold(idA.ID)
	defer releaseCompute()
	rev := f.importAndRequest(t, "select-a", "a")
	require.Eventually(t, func() bool {
		res, _, _, _ := f.computer.GetIdentityPolicyByIdentity(idB)
		return res.CurrentAtRevision >= rev
	}, 5*time.Second, time.Millisecond)

	// Trigger a regeneration, and keep it from starting.
	releaseBuild := f.buildGate.hold()
	defer releaseBuild()
	regen := ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            "test",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		ParentContext:     f.ctx,
	})

	// Another import, whose advance waits for the held computation.
	f.importAndRequest(t, "select-c", "c")

	start := time.Now()
	releaseBuild()
	require.True(t, <-regen, "regeneration failed")
	require.Less(t, time.Since(start), 500*time.Millisecond, "regeneration waited for the later import")

	releaseCompute()
	f.barrier(t)
	f.requirePolicyCurrent(t)
}

// importAndRequest imports a rule selecting app and waits until the policy
// computer has been asked to make policies current at the import's revision.
func (f *regenFixture) importAndRequest(t *testing.T, name, app string) uint64 {
	done := make(chan uint64, 1)
	f.importer.UpdatePolicy(policyUpdate(name, selecting(t, name, app), done))
	rev := f.receive(t, done)
	require.Eventually(t, func() bool { return f.computer.RequestedRevision() >= rev }, 5*time.Second, time.Millisecond)
	return rev
}
