// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/lock"
)

// SelectorPolicy represents a cached selectorPolicy, previously resolved from
// the policy repository and ready to be distilled against a set of identities
// to compute datapath-level policy configuration.
type SelectorPolicy interface {
	// Consume returns the policy in terms of connectivity to peer
	// Identities.
	Consume(owner PolicyOwner) *EndpointPolicy
}

// PolicyCache represents a cache of resolved policies for identities.
type PolicyCache struct {
	lock.Mutex

	// repo is a circular reference back to the Repository, but as
	// we create only one Repository and one PolicyCache for each
	// Cilium Agent process, these will never need to be garbage
	// collected.
	repo     *Repository
	policies map[identityPkg.NumericIdentity]*cachedSelectorPolicy
}

// NewPolicyCache creates a new cache of SelectorPolicy.
func NewPolicyCache(repo *Repository, subscribe bool) *PolicyCache {
	cache := &PolicyCache{
		repo:     repo,
		policies: make(map[identityPkg.NumericIdentity]*cachedSelectorPolicy),
	}
	if subscribe {
		identitymanager.Subscribe(cache)
	}
	return cache
}

func (cache *PolicyCache) GetSelectorCache() *SelectorCache {
	return cache.repo.GetSelectorCache()
}

// lookupOrCreate adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy.
func (cache *PolicyCache) lookupOrCreate(identity *identityPkg.Identity, create bool) SelectorPolicy {
	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity.ID]
	if create && !ok {
		cip = newCachedSelectorPolicy(identity, cache.repo.GetSelectorCache())
		cache.policies[identity.ID] = cip
	}
	return cip
}

// insert adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy.
func (cache *PolicyCache) insert(identity *identityPkg.Identity) SelectorPolicy {
	return cache.lookupOrCreate(identity, true)
}

// delete forgets about any cached SelectorPolicy that this endpoint uses.
//
// Returns true if the SelectorPolicy was removed from the cache.
func (cache *PolicyCache) delete(identity *identityPkg.Identity) (bool, *cachedSelectorPolicy) {
	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity.ID]
	if ok {
		delete(cache.policies, identity.ID)
	}
	return ok, cip
}

// updateSelectorPolicy resolves the policy for the security identity of the
// specified endpoint and stores it internally. It will skip policy resolution
// if the cached policy is already at the revision specified in the repo.
//
// Returns whether the cache was updated, or an error.
//
// Must be called with repo.Mutex held for reading.
func (cache *PolicyCache) updateSelectorPolicy(identity *identityPkg.Identity) (bool, error) {
	cache.Lock()
	cip, ok := cache.policies[identity.ID]
	cache.Unlock()
	if !ok {
		return false, fmt.Errorf("SelectorPolicy not found in cache for ID %d", identity.ID)
	}

	// As long as UpdatePolicy() is triggered from endpoint
	// regeneration, it's possible for two endpoints with the
	// *same* identity to race to update the policy here. Such
	// racing would lead to first of the endpoints using a
	// selectorPolicy that is already detached from the selector
	// cache, and thus not getting any incremental updates.
	//
	// Lock the 'cip' for the duration of the revision check and
	// the possible policy update.
	cip.Lock()
	defer cip.Unlock()

	// Don't resolve policy if it was already done for this or later revision.
	if cip.getPolicy().Revision >= cache.repo.GetRevision() {
		return false, nil
	}

	// Resolve the policies, which could fail
	selPolicy, err := cache.repo.resolvePolicyLocked(identity)
	if err != nil {
		return false, err
	}

	cip.setPolicy(selPolicy)

	return true, nil
}

// LocalEndpointIdentityAdded creates a SelectorPolicy cache entry for the
// specified Identity, without calculating any policy for it.
func (cache *PolicyCache) LocalEndpointIdentityAdded(identity *identityPkg.Identity) {
	cache.insert(identity)
}

// LocalEndpointIdentityRemoved deletes the cached SelectorPolicy for the
// specified Identity.
func (cache *PolicyCache) LocalEndpointIdentityRemoved(identity *identityPkg.Identity) {
	deleted, cip := cache.delete(identity)
	if deleted && cip != nil {
		if p := cip.getPolicy(); p != nil {
			// Detach policy resources after identity has been removed. This is
			// executed async in a separate goroutine because this callback
			// function (LocalEndpointIdentityRemoved()) can be called while the
			// endpoint lock is taken and the following Detach() can take the
			// NameManager and SelectorCache locks, which can lead to deadlocks.
			go p.Detach()
		}
	}
}

// Lookup attempts to locate the SelectorPolicy corresponding to the specified
// identity. If policy is not cached for the identity, it returns nil.
func (cache *PolicyCache) Lookup(identity *identityPkg.Identity) SelectorPolicy {
	return cache.lookupOrCreate(identity, false)
}

// UpdatePolicy resolves the policy for the security identity of the specified
// endpoint and caches it for future use.
//
// The caller must provide threadsafety for iteration over the policy
// repository.
func (cache *PolicyCache) UpdatePolicy(identity *identityPkg.Identity) error {
	_, err := cache.updateSelectorPolicy(identity)
	return err
}

// cachedSelectorPolicy is a wrapper around a selectorPolicy (stored in the
// 'policy' field). It is always nested directly in the owning policyCache,
// and is protected against concurrent writes via the policyCache mutex.
type cachedSelectorPolicy struct {
	lock.Mutex // lock is needed to synchronize parallel policy updates

	identity *identityPkg.Identity
	policy   unsafe.Pointer
}

func newCachedSelectorPolicy(identity *identityPkg.Identity, selectorCache *SelectorCache) *cachedSelectorPolicy {
	cip := &cachedSelectorPolicy{
		identity: identity,
	}
	cip.setPolicy(newSelectorPolicy(0, selectorCache))
	return cip
}

// getPolicy returns a reference to the selectorPolicy that is cached.
//
// Users should treat the result as immutable state that MUST NOT be modified.
func (cip *cachedSelectorPolicy) getPolicy() *selectorPolicy {
	return (*selectorPolicy)(atomic.LoadPointer(&cip.policy))
}

// setPolicy updates the reference to the SelectorPolicy that is cached.
// Calls Detach() on the old policy, if any.
func (cip *cachedSelectorPolicy) setPolicy(policy *selectorPolicy) {
	oldPolicy := (*selectorPolicy)(atomic.SwapPointer(&cip.policy, unsafe.Pointer(policy)))
	if oldPolicy != nil {
		// Release the references the previous policy holds on the selector cache.
		oldPolicy.Detach()
	}
}

// Consume returns the EndpointPolicy that defines connectivity policy to
// Identities in the specified cache.
//
// This denotes that a particular endpoint is 'consuming' the policy from the
// selector policy cache.
func (cip *cachedSelectorPolicy) Consume(owner PolicyOwner) *EndpointPolicy {
	// TODO: This currently computes the EndpointPolicy from SelectorPolicy
	// on-demand, however in future the cip is intended to cache the
	// EndpointPolicy for this Identity and emit datapath deltas instead.
	isHost := cip.identity.ID == identityPkg.ReservedIdentityHost
	return cip.getPolicy().DistillPolicy(owner, isHost)
}
