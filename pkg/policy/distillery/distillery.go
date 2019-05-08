// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package distillery

import (
	"fmt"

	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
)

var (
	globalPolicyCache *policyCache
)

func init() {
	globalPolicyCache = newPolicyCache()
	identitymanager.Subscribe(globalPolicyCache)
}

// SelectorPolicy represents a cached SelectorPolicy, previously resolved from
// the policy repository and ready to be distilled against a set of identities
// to compute datapath-level policy configuration.
type SelectorPolicy interface {
	// Consume returns the policy in terms of connectivity to peer
	// Identities. The callee MUST NOT modify the returned pointer.
	Consume(owner policy.PolicyOwner, cache *policy.SelectorCache) *policy.EndpointPolicy
}

// policyCache represents a cache of resolved policies for identities.
type policyCache struct {
	lock.Mutex
	policies map[identityPkg.NumericIdentity]*cachedSelectorPolicy
}

// newPolicyCache creates a new cache of SelectorPolicy.
func newPolicyCache() *policyCache {
	return &policyCache{
		policies: make(map[identityPkg.NumericIdentity]*cachedSelectorPolicy),
	}
}

// lookupOrCreate adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy
// and whether policy has been computed for this identity.
func (cache *policyCache) lookupOrCreate(identity *identityPkg.Identity, create bool) (SelectorPolicy, bool) {
	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity.ID]
	if create && !ok {
		cip = newCachedSelectorPolicy(identity)
		cache.policies[identity.ID] = cip
	}

	computed := false
	if cip != nil {
		computed = cip.getPolicy().Revision > 0
	}
	return cip, computed
}

// insert adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy
// and whether policy has been computed for this identity.
func (cache *policyCache) insert(identity *identityPkg.Identity) (SelectorPolicy, bool) {
	return cache.lookupOrCreate(identity, true)
}

// delete forgets about any cached SelectorPolicy that this endpoint uses.
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
//
// Returns whether the cache was updated, or an error.
//
// Must be called with repo.Mutex held for reading.
func (cache *policyCache) updateSelectorPolicy(repo PolicyRepository, identity *identityPkg.Identity) (bool, error) {
	revision := repo.GetRevision()

	cache.Lock()
	cip, ok := cache.policies[identity.ID]
	cache.Unlock()
	if !ok {
		return false, fmt.Errorf("SelectorPolicy not found in cache for ID %d", identity.ID)
	}

	// Don't resolve policy if it was already done for this Identity.
	currentRevision := cip.getPolicy().Revision
	if revision <= currentRevision {
		return false, nil
	}

	// Resolve the policies, which could fail
	identityPolicy, err := repo.ResolvePolicyLocked(identity)
	if err != nil {
		return false, err
	}

	// We don't cover the ResolvePolicyLocked() call above with the cache
	// Mutex because it's potentially expensive, and endpoints with
	// different identities should be able to concurrently compute policy.
	//
	// However, as long as UpdatePolicy() is triggered from endpoint
	// regeneration, it's possible for two endpoints with the *same*
	// identity to race to the revision check above, both find that the
	// policy is out-of-date, and resolve the policy then race down to
	// here. Set the pointer to the latest revision in both cases.
	//
	// Note that because repo.Mutex is held, the two racing threads will be
	// guaranteed to compute policy for the same revision of the policy.
	// We could save some CPU by, for example, forcing resolution of policy
	// for the same identity to block on a channel/lock, but this is
	// skipped for now as there are upcoming changes to the cache update
	// logic which would render such mechanisms obsolete.
	changed := revision > currentRevision
	if changed {
		cip.setPolicy(identityPolicy)
	}
	return changed, nil
}

// LocalEndpointIdentityAdded creates a SelectorPolicy cache entry for the
// specified Identity, without calculating any policy for it.
func (cache *policyCache) LocalEndpointIdentityAdded(identity *identityPkg.Identity) {
	globalPolicyCache.insert(identity)
}

// LocalEndpointIdentityRemoved deletes the cached SelectorPolicy for the
// specified Identity.
func (cache *policyCache) LocalEndpointIdentityRemoved(identity *identityPkg.Identity) {
	globalPolicyCache.delete(identity)
}

// Lookup attempts to locate the SelectorPolicy corresponding to the specified
// identity. If policy is not cached for the identity, it returns nil.
func Lookup(identity *identityPkg.Identity) SelectorPolicy {
	cip, _ := globalPolicyCache.lookupOrCreate(identity, false)
	return cip
}

// PolicyRepository is an interface which generates an SelectorPolicy for a
// particular Identity.
type PolicyRepository interface {
	ResolvePolicyLocked(*identityPkg.Identity) (*policy.SelectorPolicy, error)
	GetRevision() uint64
}

// UpdatePolicy resolves the policy for the security identity of the specified
// endpoint and caches it for future use.
//
// The caller must provide threadsafety for iteration over the provided policy
// repository.
func UpdatePolicy(repo PolicyRepository, identity *identityPkg.Identity) error {
	_, err := globalPolicyCache.updateSelectorPolicy(repo, identity)
	return err
}
