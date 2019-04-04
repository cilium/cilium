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
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/policy"
)

type cachedIdentityPolicy struct {
	users  map[Endpoint]struct{}
	policy unsafe.Pointer
}

func newCachedIdentityPolicy() *cachedIdentityPolicy {
	cip := &cachedIdentityPolicy{
		users: make(map[Endpoint]struct{}),
	}
	cip.setPolicyLocked(policy.NewIdentityPolicy())
	return cip
}

// getPolicy returns a reference to the IdentityPolicy that is cached.
//
// Users should treat the result as immutable state that MUST NOT be modified.
func (cip *cachedIdentityPolicy) getPolicy() *policy.IdentityPolicy {
	return (*policy.IdentityPolicy)(atomic.LoadPointer(&cip.policy))
}

// setPolicyLocked updates the reference to the IdentityPolicy that is cached.
func (cip *cachedIdentityPolicy) setPolicyLocked(policy *policy.IdentityPolicy) {
	atomic.StorePointer(&cip.policy, unsafe.Pointer(policy))
}

// Consume returns the EndpointPolicy that defines connectivity policy to
// Identities in the specified cache.
func (cip *cachedIdentityPolicy) Consume(owner policy.PolicyOwner, cache cache.IdentityCache) *policy.EndpointPolicy {
	// TODO: This currently computes the EndpointPolicy from IdentityPolicy
	// on-demand, however in future the cip is intended to cache the
	// EndpointPolicy for this Identity and emit datapath deltas instead.
	// Changing this requires shifting IdentityCache management
	// responsibilities from the caller into this package.
	return cip.getPolicy().DistillPolicy(owner, cache)
}
