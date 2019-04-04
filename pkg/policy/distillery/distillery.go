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
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
)

var (
	globalPolicyCache = NewPolicyCache()
)

// IdentityPolicy represents a cached IdentityPolicy, previously resolved from
// the policy repository and ready to be distilled against a set of identities
// to compute datapath-level policy configuration.
type IdentityPolicy interface {
	// Consume returns the policy in terms of connectivity to peer
	// Identities. The callee MUST NOT modify the returned pointer.
	Consume(owner policy.PolicyOwner, cache cache.IdentityCache) *policy.EndpointPolicy
}

// policyCache represents a cache of resolved policies for identities.
type policyCache struct {
	lock.Mutex
	policies map[*identityPkg.Identity]*cachedIdentityPolicy
}

// NewPolicyCache creates a new cache of IdentityPolicy.
func NewPolicyCache() *policyCache {
	return &policyCache{
		policies: make(map[*identityPkg.Identity]*cachedIdentityPolicy),
	}
}

// upsert adds the specified Identity to the policy cache, with a reference
// from the specified Endpoint, then returns the threadsafe copy of the policy
// and whether policy has been computed for this identity.
func (cache *policyCache) upsert(identity *identityPkg.Identity, ep Endpoint) IdentityPolicy {
	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity]
	if !ok {
		cip = newCachedIdentityPolicy()
		cache.policies[identity] = cip
	}
	cip.users[ep] = struct{}{}

	return cip
}

// remove forgets about any cached IdentityPolicy that this endpoint uses.
//
// Returns true if the IdentityPolicy was removed from the cache.
func (cache *policyCache) remove(ep Endpoint) (bool, error) {
	identity := ep.GetSecurityIdentity()

	cache.Lock()
	defer cache.Unlock()
	cip, ok := cache.policies[identity]
	if !ok {
		return false, fmt.Errorf("no cached IdentityPolicy for identity %d", identity.ID)
	}

	changed := false
	delete(cip.users, ep)
	if len(cip.users) == 0 {
		// TODO: Add deferred removal window in case the IdentityPolicy
		//       may be re-used some time soon?
		delete(cache.policies, identity)
		changed = true
	}
	return changed, nil
}

// updateIdentityPolicy resolves the policy for the security identity of the
// specified endpoint and stores it internally.
//
// Returns whether the cache was updated, or an error.
//
// Must be called with repo.Mutex held for reading.
func (cache *policyCache) updateIdentityPolicy(repo PolicyRepository, ep Endpoint) (bool, error) {
	identity := ep.GetSecurityIdentity()

	cache.Lock()
	cip, ok := cache.policies[identity]
	cache.Unlock()
	if !ok {
		return false, fmt.Errorf("IdentityPolicy not found in cache for ID %d", identity.ID)
	}

	// Resolve the policies, which could fail
	identityPolicy, err := repo.ResolvePolicyLocked(identity)
	if err != nil {
		return false, err
	}

	cache.Lock()
	defer cache.Unlock()
	cip.setPolicyLocked(identityPolicy)
	return true, nil
}

// Upsert notifies the global policy cache that the specified endpoint requires
// a reference to an identity policy, and returns the cached identity policy
// for that identity.
func Upsert(ep Endpoint) IdentityPolicy {
	identity := ep.GetSecurityIdentity()
	cip := globalPolicyCache.upsert(identity, ep)
	return cip
}

// Remove a cached IdentityPolicy reference for the specified endpoint.
func Remove(ep Endpoint) error {
	_, err := globalPolicyCache.remove(ep)
	return err
}

// PolicyRepository is an interface which generates an IdentityPolicy for a
// particular Identity.
type PolicyRepository interface {
	ResolvePolicyLocked(*identityPkg.Identity) (*policy.IdentityPolicy, error)
}

// Endpoint represents a user of an IdentityPolicy. It is used for managing
// the lifetime of the cached policy.
type Endpoint interface {
	policy.PolicyOwner
}

// UpdatePolicy resolves the policy for the security identity of the specified
// endpoint and caches it for future use.
//
// The caller must provide threadsafety for iteration over the provided policy
// repository.
func UpdatePolicy(repo PolicyRepository, ep Endpoint) error {
	_, err := globalPolicyCache.updateIdentityPolicy(repo, ep)
	return err
}
