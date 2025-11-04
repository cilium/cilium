// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"sync"
	"sync/atomic"

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

// lookup is the same function as lookupLocked, except that it grabs the lock of the cache
func (cache *policyCache) lookup(identity *identityPkg.Identity) (*cachedSelectorPolicy, bool) {
	cache.Lock()
	defer cache.Unlock()
	return cache.lookupLocked(identity)
}

// lookupLocked returns the selector policy for the given identity. If the identity is not present in the cache it
// will return nil and false
func (cache *policyCache) lookupLocked(identity *identityPkg.Identity) (*cachedSelectorPolicy, bool) {
	cip, ok := cache.policies[identity.ID]
	if !ok {
		return nil, false
	}
	return cip, true
}

// GetPolicySnapshot returns a snapshot of the current policy cache.
// The policy snapshot has the lock order as: Repository.Mutex before policyCache.Mutex.
func (cache *policyCache) GetPolicySnapshot() map[identityPkg.NumericIdentity]SelectorPolicy {
	cache.Lock()
	defer cache.Unlock()
	snapshot := make(map[identityPkg.NumericIdentity]SelectorPolicy, len(cache.policies))
	for k, v := range cache.policies {
		selPolicy := v.getPolicy()
		if selPolicy != nil {
			snapshot[k] = selPolicy
		}
	}
	return snapshot
}

// insert adds the specified Identity to the policy cache
func (cache *policyCache) insert(identity *identityPkg.Identity) *cachedSelectorPolicy {
	cache.Lock()
	defer cache.Unlock()

	wg := sync.WaitGroup{}
	// This is only used for updating identities in the subject selector cache, that is used to index and track
	// policies selecting identities used on the local node
	cache.repo.subjectSelectorCache.UpdateIdentities(identityPkg.IdentityMap{identity.ID: identity.LabelArray}, nil, &wg)

	cip, ok := cache.lookupLocked(identity)
	if !ok {
		cip = newCachedSelectorPolicy(identity)
		cache.policies[identity.ID] = cip
	}
	return cip
}

// delete forgets about any cached SelectorPolicy that this endpoint uses.
//
// Returns true if the SelectorPolicy was removed from the cache.
func (cache *policyCache) delete(identity *identityPkg.Identity) bool {
	cache.Lock()
	defer cache.Unlock()

	wg := sync.WaitGroup{}
	// This is only used for updating identities in the subject selector cache, that is used to index and track
	// policies selecting identities used on the local node
	cache.repo.subjectSelectorCache.UpdateIdentities(nil, identityPkg.IdentityMap{identity.ID: identity.LabelArray}, &wg)

	cip, ok := cache.policies[identity.ID]
	if ok {
		delete(cache.policies, identity.ID)
		selPolicy := cip.getPolicy()
		if selPolicy != nil {
			selPolicy.detach(true, 0)
		}
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
// Returns whether the cache was updated, or an error. It will return an error if the
// identity is not in use by any endpoint on the node. That can happen in cases where
// an endpoint changed its identity during policy regeneration, where the regeneration
// is still referring to the old identity.
//
// Must be called with repo.Mutex held for reading.
func (cache *policyCache) updateSelectorPolicy(identity *identityPkg.Identity, endpointID uint64) (*selectorPolicy, bool, error) {
	cip, ok := cache.lookup(identity)
	if !ok {
		return nil, false, fmt.Errorf("SelectorPolicy not found in cache for ID %d", identity.ID)
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
	if selPolicy := cip.getPolicy(); selPolicy != nil && selPolicy.Revision >= cache.repo.GetRevision() {
		return selPolicy, false, nil
	}

	// Resolve the policies, which could fail
	selPolicy, err := cache.repo.resolvePolicyLocked(identity)
	if err != nil {
		return nil, false, err
	}

	cip.setPolicy(selPolicy, endpointID)

	return selPolicy, true, nil
}

// LocalEndpointIdentityAdded creates a SelectorPolicy cache entry for the
// specified Identity, without calculating any policy for it.
func (cache *policyCache) LocalEndpointIdentityAdded(identity *identityPkg.Identity) {
	cache.insert(identity)
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
	selPolicy := cip.getPolicy()
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
		if missing && cs.Selects(remoteID) {
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

// getPolicy returns a reference to the selectorPolicy that is cached.
//
// Users should treat the result as immutable state that MUST NOT be modified.
func (cip *cachedSelectorPolicy) getPolicy() *selectorPolicy {
	return cip.policy.Load()
}

// setPolicy updates the reference to the SelectorPolicy that is cached.
// Calls Detach() on the old policy, if any. It passes the endpointID of
// the endpoint that initiated the old selector policy detach. Since detach
// can trigger endpoint regenerations of all it users, this ensures
// that endpoints do not continuously update themselves.
func (cip *cachedSelectorPolicy) setPolicy(policy *selectorPolicy, endpointID uint64) {
	oldPolicy := cip.policy.Swap(policy)
	if oldPolicy != nil {
		// Release the references the previous policy holds on the selector cache.
		oldPolicy.detach(false, endpointID)
	}
}
