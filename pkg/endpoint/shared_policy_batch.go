// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"errors"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// SharedPolicyBatch collects the syncs to the shared policy map of endpoints that apply
// incremental policy changes together, see Endpoint.ApplyPolicyMapChangesBatched, and syncs
// them at once. Endpoints that share a rule set and all get the same change then update the
// rule set in place, instead of each switching to a copy of it. The zero value is ready to use.
type SharedPolicyBatch struct {
	mu    lock.Mutex
	syncs []*sharedPolicySync
}

// sharedPolicySync is an endpoint's sync to the shared policy map in a SharedPolicyBatch.
type sharedPolicySync struct {
	endpoint *Endpoint
	overlay  *policymap.EndpointOverlay
	// policy and changes are the endpoint's desired policy and the number of incremental
	// changes applied to it, when the sync was prepared.
	policy  *policy.EndpointPolicy
	changes uint64
	// revertible reverts the endpoint's other changes, e.g. to its Envoy network policy.
	revertible revert.Revertible
}

func (b *SharedPolicyBatch) add(s *sharedPolicySync) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.syncs = append(b.syncs, s)
}

// Sync syncs the collected endpoint policies to the shared policy map. It then calls done for
// each of the endpoints with the result, as Endpoint.ApplyPolicyMapChanges returns it: an
// error, or the revertible of the endpoint's changes, which the caller must revert or
// finalize. done may be called concurrently.
func (b *SharedPolicyBatch) Sync(done func(e *Endpoint, err error, revertible revert.Revertible)) {
	b.mu.Lock()
	syncs := b.syncs
	b.syncs = nil
	b.mu.Unlock()
	if len(syncs) == 0 {
		return
	}

	overlays := make([]*policymap.EndpointOverlay, len(syncs))
	for i, s := range syncs {
		overlays[i] = s.overlay
	}
	// All endpoints use the same policy map factory.
	errs := syncs[0].endpoint.policyMapFactory.SyncEndpointOverlays(overlays)

	// Each endpoint handles its result with its lock held. Do it in parallel, so that an
	// endpoint that is locked for a while, e.g. by its regeneration, does not delay the
	// others.
	var wg sync.WaitGroup
	for i, s := range syncs {
		wg.Go(func() {
			revertible, err := s.finish(errs[i])
			done(s.endpoint, err, revertible)
		})
	}
	wg.Wait()
}

// finish handles the result of the endpoint's sync, unless a later sync of the endpoint
// superseded it. It returns the revertible of the endpoint's changes, unless it reverted them
// because the sync failed.
func (s *sharedPolicySync) finish(err error) (revert.Revertible, error) {
	e := s.endpoint
	if lockErr := e.lockAlive(); lockErr != nil {
		return s.revertible, lockErr
	}
	defer e.unlock()

	if errors.Is(err, policymap.ErrEndpointOverlaySuperseded) || e.sharedPolicyPending != s.overlay {
		// The later sync handles its own result.
		return s.revertible, nil
	}
	e.sharedPolicyPending = nil

	synced := s.policy
	if synced != e.desiredPolicy || s.changes != e.sharedPolicyChanges {
		// The desired policy changed after the sync was prepared.
		synced = nil
	}
	if err := e.sharedPolicySyncedLocked(err, synced); err != nil {
		e.logStatusLocked(Policy, Failure, err.Error())
		if s.revertible != nil {
			_ = s.revertible.Revert()
		}
		return nil, err
	}
	e.LogStatusOKLocked(Policy, "Policy Map changes applied")
	return s.revertible, nil
}
