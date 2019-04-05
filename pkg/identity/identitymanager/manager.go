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

package identitymanager

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	GlobalIdentityManager = NewIdentityManager()
)

type IdentityManager struct {
	mutex      lock.RWMutex
	identities map[*identity.Identity]*identityMetadata
}

type identityMetadata struct {
	refCount uint
}

// NewIdentityManager returns an initialized IdentityManager.
func NewIdentityManager() *IdentityManager {
	return &IdentityManager{
		identities: make(map[*identity.Identity]*identityMetadata),
	}
}

// Upsert inserts the identity into the GlobalIdentityManager.
func Upsert(identity *identity.Identity) {
	GlobalIdentityManager.Upsert(identity)
}

// Delete deletes the identity from the GlobalIdentityManager.
func Delete(identity *identity.Identity) {
	GlobalIdentityManager.Delete(identity)
}

// Upsert inserts the identity into the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// incremented.
func (idm *IdentityManager) Upsert(identity *identity.Identity) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	idMeta, exists := idm.identities[identity]
	if !exists {
		idm.identities[identity] = &identityMetadata{
			refCount: 1,
		}
	} else {
		idMeta.refCount += 1
	}
}

// Delete deletes the identity from the identity manager. If the identity is
// already in the identity manager, the reference count for the identity is
// decremented. If the identity is not in the cache, this is a no-op. If the
// ref count becomes zero, the identity is removed from the cache.
func (idm *IdentityManager) Delete(identity *identity.Identity) {
	idm.mutex.Lock()
	defer idm.mutex.Unlock()

	idMeta, exists := idm.identities[identity]
	if !exists {
		return
	} else {
		idMeta.refCount -= 1
		if idMeta.refCount == 0 {
			delete(idm.identities, identity)
		}
	}
}
