// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

type PolicyRecomputer interface {
	RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error)
	RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error)
	UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], fromRev, toRev uint64)
	GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool)
}

type Result struct {
	Identity             identity.NumericIdentity
	NewPolicy, OldPolicy policy.SelectorPolicy
	Revision             uint64
	NeedsRelease         bool
	Err                  error
}

type computeRequest struct {
	identity *identity.Identity
	toRev    uint64
	done     chan struct{}
}

func (r *IdentityPolicyComputer) UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], _, toRev uint64) {
	// The lock order is IdentityManager.mutex before reqsMu, since the
	// IdentityManager observer takes reqsMu. Resolve identities, which takes
	// IdentityManager.mutex, before locking reqsMu.
	ids := make([]*identity.Identity, 0, idsToRegen.Len())
	for id := range idsToRegen.Members() {
		if idd := r.idmanager.Get(&id); idd != nil {
			ids = append(ids, idd)
		} else {
			r.logger.Debug("Policy recomputation skipped due to non-local identity", logfields.Identity, id)
		}
	}

	r.reqsMu.Lock()
	for _, idd := range ids {
		r.enqueueLocked(idd, toRev)
	}
	r.reqsMu.Unlock()
	r.notifyTrigger()
}

// enqueueLocked appends or coalesces a request and returns the done channel.
// Must be called with r.reqsMu held. The caller must notifyTrigger after
// unlocking.
func (r *IdentityPolicyComputer) enqueueLocked(identity *identity.Identity, toRev uint64) <-chan struct{} {
	for i, existing := range r.reqs {
		if existing.identity.ID != identity.ID {
			continue
		}
		if toRev > existing.toRev {
			r.reqs[i].toRev = toRev
		}
		return r.reqs[i].done
	}
	req := computeRequest{
		identity: identity,
		toRev:    toRev,
		done:     make(chan struct{}),
	}
	r.reqs = append(r.reqs, req)
	return req.done
}

func (r *IdentityPolicyComputer) notifyTrigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// RecomputeIdentityPolicy schedules a policy recomputation for identity at
// toRev. The returned channel closes once the result is committed to the
// table. A pending request for the same identity is reused, bumping its toRev
// to max(existing, toRev), so there is at most one in-flight request per
// identity.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error) {
	r.reqsMu.Lock()
	done := r.enqueueLocked(identity, toRev)
	r.reqsMu.Unlock()
	r.notifyTrigger()
	return done, nil
}

// RecomputeIdentityPolicyForAllIdentities recomputes policy for all local identities.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error) {
	ws := statedb.NewWatchSet()

	r.logger.Info("Recomputing policy for all identities")
	// GetAll takes IdentityManager.mutex. Call it before locking reqsMu (see
	// UpdatePolicy).
	ids := r.idmanager.GetAll()

	r.reqsMu.Lock()
	for _, id := range ids {
		ws.Add(r.enqueueLocked(id, toRev))
	}
	r.reqsMu.Unlock()
	r.notifyTrigger()
	return ws, nil
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool) {
	return r.tbl.GetWatch(r.db.ReadTxn(), PolicyComputationByIdentity(identity))
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool) {
	if identity == nil {
		return Result{}, 0, nil, false
	}
	return r.GetIdentityPolicyByNumericIdentity(identity.ID)
}

// processRequests drains computation requests and processes them in batches.
// Single requests are processed immediately. Bursts are naturally batched.
func (r *IdentityPolicyComputer) processRequests(ctx context.Context) error {
	type pending struct {
		computeRequest
		rev statedb.Revision // statedb revision for CompareAndSwap
	}

	for {
		select {
		case <-ctx.Done():
			// Close any queued requests so waiters don't hang.
			r.reqsMu.Lock()
			abandoned := r.reqs
			r.reqs = nil
			r.reqsMu.Unlock()
			r.logger.Debug("Draining pending policy computation requests on shutdown", logfields.Count, len(abandoned))
			for _, req := range abandoned {
				close(req.done)
			}
			return nil
		case <-r.trigger:
		}

		r.reqsMu.Lock()
		batch := r.reqs
		r.reqs = nil
		r.reqsMu.Unlock()
		if len(batch) == 0 {
			continue
		}

		r.logger.Debug("Processing policy computation batch", logfields.Count, len(batch))

		// Check which requests actually need computation.
		rtxn := r.db.ReadTxn()
		var work []pending
		for _, req := range batch {
			obj, rev, found := r.tbl.Get(rtxn, PolicyComputationByIdentity(req.identity.ID))
			if found && obj.Revision >= req.toRev {
				close(req.done)
				continue
			}
			work = append(work, pending{req, rev})
		}
		if len(work) == 0 {
			continue
		}

		type result struct {
			pending
			res Result
		}
		results := make([]result, len(work))
		var wg sync.WaitGroup
		for i, w := range work {
			wg.Go(func() {
				start := time.Now()
				results[i].pending = w
				results[i].res.Identity = w.identity.ID
				results[i].res.NewPolicy, results[i].res.Revision, results[i].res.OldPolicy, results[i].res.NeedsRelease, results[i].res.Err = r.repo.ComputeSelectorPolicy(w.identity, w.toRev)
				outcome := metrics.LabelValueOutcomeSuccess
				if results[i].res.Err != nil {
					outcome = metrics.LabelValueOutcomeFailure
				}
				metrics.EndpointRegenerationTimeStats.
					WithLabelValues("selectorPolicyCalculation", outcome).
					Observe(time.Since(start).Seconds())
			})
		}
		wg.Wait()

		// Commit in a single WriteTxn.
		wtxn := r.db.WriteTxn(r.tbl)
		var retry []computeRequest
		for i := range results {
			if results[i].res.Err != nil {
				// Cancel the retry because the identity no longer exists.
				if errors.Is(results[i].res.Err, policy.ErrSelectorPolicyNotCached) {
					r.logger.Debug("Skipping policy computation for removed identity",
						logfields.Identity, results[i].res.Identity,
					)
					results[i].res = Result{}
					continue
				}
				// This error will result in the relevant endpoints failing
				// to regenerate.
				r.logger.Error("Policy computation failed for identity",
					logfields.Identity, results[i].res.Identity,
					logfields.Error, results[i].res.Err,
				)
				// Re-enqueue so a transient failure (e.g. cert fetch)
				// doesn't leave statedb without an entry forever.
				//
				// Retry is unbounded with no backoff. This matches the
				// pre-cell behavior where endpoint regeneration retried
				// the policy computation inline. Dropping a computation
				// would leave endpoints on a stale policy, so we always
				// retry.
				retry = append(retry, computeRequest{
					identity: results[i].identity,
					toRev:    results[i].toRev,
					done:     make(chan struct{}),
				})
				results[i].res = Result{}
				continue
			}
			// CAS failure means a delete for this identity raced us. If
			// the delete ran getPolicy() before our setPolicy() published
			// NewPolicy, NewPolicy remains attached to the SelectorCache.
			// Detach both NewPolicy and OldPolicy here, since the success
			// path's OldPolicy detach loop below skips zeroed results.
			if _, _, err := r.tbl.CompareAndSwap(wtxn, results[i].rev, results[i].res); err != nil {
				if results[i].res.NeedsRelease {
					if results[i].res.NewPolicy != nil {
						results[i].res.NewPolicy.Supersede()
					}
					if results[i].res.OldPolicy != nil {
						results[i].res.OldPolicy.Supersede()
					}
				}
				results[i].res = Result{}
			}
		}
		wtxn.Commit()

		if len(retry) > 0 {
			r.reqsMu.Lock()
			r.reqs = append(r.reqs, retry...)
			r.reqsMu.Unlock()
			select {
			case r.trigger <- struct{}{}:
			default:
			}
		}

		for _, cr := range results {
			close(cr.done)
			if cr.res.Identity == 0 {
				continue // CAS failed
			}
			r.logger.Debug("Policy recomputation completed",
				logfields.Identity, cr.res.Identity,
				logfields.PolicyRevision, cr.toRev,
			)
			if cr.res.OldPolicy != nil && cr.res.NeedsRelease {
				cr.res.OldPolicy.Supersede()
			}
		}
	}
}

func (r *IdentityPolicyComputer) handlePolicyCacheEvent(ctx context.Context, event policy.PolicyCacheChange) error {
	r.logger.Debug("Handle policy cache event", logfields.Identity, event.ID)

	// The identity may already be gone from the manager by now, so clean up
	// statedb on delete.
	if event.Kind == policy.PolicyChangeDelete {
		// Drop pending requests for this identity and close their done
		// channels. No Result is committed. Endpoint regen retries on
		// not-found.
		r.reqsMu.Lock()
		kept := r.reqs[:0]
		for _, req := range r.reqs {
			if req.identity.ID == event.ID {
				close(req.done)
				continue
			}
			kept = append(kept, req)
		}
		r.reqs = kept
		r.reqsMu.Unlock()

		wtxn := r.db.WriteTxn(r.tbl)
		obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(event.ID))
		if !found {
			wtxn.Abort()
			return nil
		}
		_, _, err := r.tbl.Delete(wtxn, obj)
		if err != nil {
			wtxn.Abort()
			return fmt.Errorf("failed to delete from statedb policy computation table: %w", err)
		}
		wtxn.Commit()
		return nil
	}

	if event.Identity == nil {
		return nil
	}

	if event.Kind == policy.PolicyChangeInsert {
		_, err := r.RecomputeIdentityPolicy(event.Identity, 0)
		if err != nil {
			return err
		}
	}
	return nil
}
