// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync/atomic"

	"github.com/cilium/cilium/pkg/container/versioned"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/lock"
)

// policyCache represents a cache of resolved policies for identities.
type policyCache struct {
	lock.Mutex

	// repo is a circular reference back to the Repository, but as
	// we create only one Repository and one PolicyCache for each
	// Cilium Agent process, these will never need to be garbage
	// collected.
	repo     *Repository
	policies map[identityPkg.NumericIdentity]*cachedSelectorPolicy
}

// newPolicyCache creates a new cache of SelectorPolicy.
func newPolicyCache(repo *Repository, idmgr identitymanager.IDManager) *policyCache {
	cache := &policyCache{
		repo:     repo,
		policies: make(map[identityPkg.NumericIdentity]*cachedSelectorPolicy),
	}
	if idmgr != nil {
		idmgr.Subscribe(cache)
	}
	return cache
}

// lookupOrCreate adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy.
// A new empty policy is returned if there is no policy for the given 'identity'.
func (cache *policyCache) lookupOrCreate(identity *identityPkg.Identity) *cachedSelectorPolicy {
	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity.ID]
	if !ok || cip == nil {
		cip = newCachedSelectorPolicy(identity)
		cache.policies[identity.ID] = cip
	}
	return cip
}

// GetCurrentPolicy returns a snapshot of the current policy for the given identity.
// Returned policy can already be stale, but generally is the revision that was previously
// plumbed to the datapath.
func (cache *policyCache) GetCurrentPolicy(identity *identityPkg.Identity) SelectorPolicy {
	cache.Lock()
	defer cache.Unlock()

	cip, ok := cache.policies[identity.ID]
	if ok && cip != nil {
		return cip.policy.Load()
	}
	return nil
}

// GetPolicySnapshot returns a snapshot of the current policy cache.
// The policy snapshot has the lock order as: Repository.Mutex before policyCache.Mutex.
func (cache *policyCache) GetPolicySnapshot() map[identityPkg.NumericIdentity]SelectorPolicy {
	cache.Lock()
	defer cache.Unlock()
	snapshot := make(map[identityPkg.NumericIdentity]SelectorPolicy, len(cache.policies))
	for k, v := range cache.policies {
		selPolicy := v.policy.Load()
		if selPolicy != nil {
			snapshot[k] = selPolicy
		}
	}
	return snapshot
}

// delete removes the cached SelectorPolicy for the given identity.
//
// Returns true if the SelectorPolicy was removed from the cache.
func (cache *policyCache) delete(identity *identityPkg.Identity) bool {
	cache.Lock()
	defer cache.Unlock()
	_, ok := cache.policies[identity.ID]
	if ok {
		delete(cache.policies, identity.ID)
	}
	return ok
}

// updateSelectorPolicy resolves the policy for the security identity of the
// specified endpoint and stores it internally. It will skip policy resolution
// if the cached policy is already at the revision specified in the repo.
// The endpointID specifies which endpoint initiated this selector policy
// update. This ensures that endpoints are not continuously triggering regenerations
// of themselves if the selector policy is created and initiates a regeneration trigger
// on detach.
//
// Returns whether the cache was updated, or an error.
//
// Must be called with repo.Mutex held for reading.
func (cache *policyCache) updateSelectorPolicy(identity *identityPkg.Identity, endpointID uint64) (*selectorPolicy, bool, error) {
	cip := cache.lookupOrCreate(identity)

	// As long as UpdatePolicy() is triggered from endpoint
	// regeneration, it's possible for two endpoints with the
	// *same* identity to race to update the policy here. Such
	// racing would lead to first of the endpoints using a
	// selectorPolicy that is already detached from the selector
	// cache, and thus not getting any incremental updates.
	//
	// Lock the 'cip' for the duration of the revision check and
	// the possible policy update, so that the policy is only computed
	// by the first endpoint that gets to lock, and all of them use the
	// same resolved selector policy.
	cip.Lock()
	defer cip.Unlock()

	selPolicy := cip.policy.Load()
	if selPolicy == nil || selPolicy.isStale(cache.repo.GetRevision()) {
		// Resolve the policies, which could fail
		var err error
		selPolicy, err = cache.repo.resolvePolicyLocked(identity)
		if err != nil {
			return nil, false, err
		}
		cip.policy.Store(selPolicy)
		return selPolicy, true, nil
	}

	return selPolicy, false, nil
}

// LocalEndpointIdentityAdded is not needed; we only care about local endpoint
// deletion
func (cache *policyCache) LocalEndpointIdentityAdded(identity *identityPkg.Identity) {
}

// LocalEndpointIdentityRemoved deletes the cached SelectorPolicy for the
// specified Identity.
func (cache *policyCache) LocalEndpointIdentityRemoved(identity *identityPkg.Identity) {
	cache.delete(identity)
}

// getAuthTypes returns the AuthTypes required by the policy between the localID and remoteID, if
// any, otherwise returns nil.
func (cache *policyCache) getAuthTypes(localID, remoteID identityPkg.NumericIdentity) AuthTypes {
	cache.Lock()
	cip, ok := cache.policies[localID]
	cache.Unlock()
	if !ok {
		return nil // No policy for localID (no endpoint with localID)
	}

	// SelectorPolicy is const after it has been created, so no locking needed to access it
	selPolicy := cip.policy.Load()
	if selPolicy == nil {
		return nil
	}

	var resTypes AuthTypes
	for cs, authTypes := range selPolicy.L4Policy.authMap {
		missing := false
		for authType := range authTypes {
			if _, exists := resTypes[authType]; !exists {
				missing = true
				break
			}
		}
		// Only check if 'cs' selects 'remoteID' if one of the authTypes is still missing
		// from the result
		if missing && cs.Selects(versioned.Latest(), remoteID) {
			if resTypes == nil {
				resTypes = make(AuthTypes, 1)
			}
			for authType := range authTypes {
				resTypes[authType] = struct{}{}
			}
		}
	}
	return resTypes
}

// cachedSelectorPolicy is a wrapper around a selectorPolicy (stored in the
// 'policy' field). It is always nested directly in the owning policyCache,
// and is protected against concurrent writes via the policyCache mutex.
type cachedSelectorPolicy struct {
	lock.Mutex // lock is needed to synchronize parallel policy updates

	identity *identityPkg.Identity
	policy   atomic.Pointer[selectorPolicy]
}

func newCachedSelectorPolicy(identity *identityPkg.Identity) *cachedSelectorPolicy {
	cip := &cachedSelectorPolicy{
		identity: identity,
	}
	return cip
}
