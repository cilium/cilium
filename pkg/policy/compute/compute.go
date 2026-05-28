// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"sync"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
)

type PolicyRecomputer interface {
	RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error)
	RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error)
	UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], fromRev, toRev uint64)
	GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetAuthTypes(localID, remoteID identity.NumericIdentity) policyTypes.AuthTypes
	GetPolicySnapshot() map[identity.NumericIdentity]policy.SelectorPolicy
}

type Result struct {
	Identity             identity.NumericIdentity
	NewPolicy, OldPolicy policy.SelectorPolicy
	// Revision is the repository revision this policy was computed at. It is
	// how processRequests tells whether a requested computation has already
	// run, so it must only ever be set by an actual computation. Use
	// CurrentAtRevision to ask how far forward the policy is still valid.
	Revision uint64
	// CurrentAtRevision is the highest repository revision this policy is
	// known to be correct for. It starts equal to Revision and is advanced,
	// without recomputing, by policy updates that do not select this identity.
	// Always >= Revision.
	CurrentAtRevision uint64
	Err               error
}

type computeRequest struct {
	identity *identity.Identity
	toRev    uint64
	done     chan struct{}
}

// advanceRequest carries a policy update's revision range. idsToRegen holds the
// identities it selected, which an advance must skip. See applyAdvances.
type advanceRequest struct {
	idsToRegen     set.Set[identity.NumericIdentity]
	fromRev, toRev uint64
}

func (r *IdentityPolicyComputer) UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
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
	// Identities this update did not select keep their committed policy, but
	// still need their revision advanced. The computation loop owns the table,
	// so hand the work to it rather than writing here.
	r.advances = append(r.advances, advanceRequest{
		idsToRegen: idsToRegen,
		fromRev:    fromRev,
		toRev:      toRev,
	})
	r.reqsMu.Unlock()
	r.notifyTrigger()
}

// applyAdvances raises CurrentAtRevision for every committed policy that an
// update did not select.
//
// An identity absent from an update's idsToRegen is not selected by any of the
// rules that changed, so its already-committed policy is still correct at toRev
// and needs no recomputation. Recording that fact mirrors what the importer
// does for endpoints that are already exposed, which have their revision bumped
// without a regeneration. Without it, an endpoint exposed after the importer
// snapshotted the endpoint list has no way to learn that its policy is already
// current, and adopts the pre-import revision as its realized one.
//
// A policy is only carried forward if it was already current at the revision
// this update started from. That keeps the claim inductive: an identity whose
// policy is still awaiting (or has failed) a computation for an earlier
// revision is never marked current for a later one.
//
// Must be called from processRequests with wtxn open, so that these writes
// cannot invalidate a CompareAndSwap performed by a concurrent recomputation.
func (r *IdentityPolicyComputer) applyAdvances(wtxn statedb.WriteTxn, advances []advanceRequest) {
	if len(advances) == 0 {
		return
	}
	for obj := range r.tbl.All(wtxn) {
		target := revisionAfterAdvances(advances, obj.Identity, obj.CurrentAtRevision)
		if target == obj.CurrentAtRevision {
			continue
		}
		obj.CurrentAtRevision = target
		if _, _, err := r.tbl.Insert(wtxn, obj); err != nil {
			r.logger.Error("Failed to advance policy computation revision",
				logfields.Identity, obj.Identity,
				logfields.PolicyRevisionCurrentAt, target,
				logfields.Error, err)
		}
	}
}

// revisionAfterAdvances returns the revision the identity's policy is current at
// once the given updates have been applied in order.
func revisionAfterAdvances(advances []advanceRequest, id identity.NumericIdentity, current uint64) uint64 {
	for _, adv := range advances {
		if current < adv.fromRev || current >= adv.toRev {
			continue
		}
		if adv.idsToRegen.Has(id) {
			continue
		}
		current = adv.toRev
	}
	return current
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
		rev       statedb.Revision      // statedb revision for CompareAndSwap
		oldPolicy policy.SelectorPolicy // the committed policy, superseded after the new one commits
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
		advances := r.advances
		r.advances = nil
		r.reqsMu.Unlock()
		if len(batch) == 0 && len(advances) == 0 {
			continue
		}

		r.logger.Debug("Processing policy computation batch", logfields.Count, len(batch))

		// Check which requests actually need computation.
		rtxn := r.db.ReadTxn()
		var work []pending
		for _, req := range batch {
			obj, rev, found := r.tbl.Get(rtxn, PolicyComputationByIdentity(req.identity.ID))
			// Revision, not CurrentAtRevision: only a computation that actually
			// ran can satisfy a request. See applyAdvances.
			if found && obj.Revision >= req.toRev {
				close(req.done)
				continue
			}
			// The currently committed policy becomes the old one once this
			// recomputation commits its replacement.
			work = append(work, pending{computeRequest: req, rev: rev, oldPolicy: obj.NewPolicy})
		}
		if len(work) == 0 {
			if len(advances) > 0 {
				wtxn := r.db.WriteTxn(r.tbl)
				r.applyAdvances(wtxn, advances)
				wtxn.Commit()
			}
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
				results[i].res.OldPolicy = w.oldPolicy
				results[i].res.NewPolicy, results[i].res.Revision, results[i].res.Err = r.repo.ComputeSelectorPolicy(w.identity)
				// A freshly computed policy is current as of the revision it
				// was computed at.
				results[i].res.CurrentAtRevision = results[i].res.Revision
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
			// CAS failure means a delete for this identity raced us. The
			// new policy was Attach()ed by resolvePolicyLocked, so supersede
			// it here to release its SelectorCache references. The old policy
			// is released by the delete path in LocalEndpointIdentityRemoved.
			if _, _, err := r.tbl.CompareAndSwap(wtxn, results[i].rev, results[i].res); err != nil {
				if results[i].res.NewPolicy != nil {
					results[i].res.NewPolicy.Supersede()
				}
				results[i].res = Result{}
			}
		}
		// After the CompareAndSwaps above, so that advancing a revision cannot
		// invalidate a recomputation's expected statedb revision.
		r.applyAdvances(wtxn, advances)
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
			if cr.res.OldPolicy != nil {
				cr.res.OldPolicy.Supersede()
			}
		}
	}
}

// LocalEndpointIdentityAdded is part of the identitymanager.Observer
// interface.
//
// The subject selectorcache must be updated with the identity before
// recomputation, otherwise policy will not be computed properly.
func (r *IdentityPolicyComputer) LocalEndpointIdentityAdded(id *identity.Identity) {
	r.repo.UpdateIdentities(identity.IdentityMap{id.ID: id.Labels}, nil)
	_, _ = r.RecomputeIdentityPolicy(id, 0)
}

// LocalEndpointIdentityRemoved is part of the identitymanager.Observer interface.
func (r *IdentityPolicyComputer) LocalEndpointIdentityRemoved(id *identity.Identity) {
	r.logger.Debug("Identity removed", logfields.Identity, id.ID)

	// See comment on LocalEndpointIdentityAdded.
	r.repo.UpdateIdentities(nil, identity.IdentityMap{id.ID: id.Labels})

	// Drop any pending compute requests for this identity so we don't keep
	// re-running a stale computation.
	r.reqsMu.Lock()
	kept := r.reqs[:0]
	for _, req := range r.reqs {
		if req.identity.ID == id.ID {
			close(req.done)
			continue
		}
		kept = append(kept, req)
	}
	r.reqs = kept
	r.reqsMu.Unlock()

	wtxn := r.db.WriteTxn(r.tbl)
	obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(id.ID))
	if !found {
		wtxn.Abort()
		return
	}
	if _, _, err := r.tbl.Delete(wtxn, obj); err != nil {
		wtxn.Abort()
		r.logger.Error("Failed to delete from policy computation table",
			logfields.Identity, id.ID,
			logfields.Error, err)
		return
	}
	wtxn.Commit()

	// Release the policy's selectors. Supersede after Commit so the detach
	// runs outside the write txn, matching processRequests.
	if obj.NewPolicy != nil {
		obj.NewPolicy.Supersede()
	}
}
