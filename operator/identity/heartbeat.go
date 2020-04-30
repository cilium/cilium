// Copyright 2019-2020 Authors of Cilium
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

package identity

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "identity-heartbeat")
)

// IdentityHeartbeatStore keeps track of the heartbeat of identities
type IdentityHeartbeatStore struct {
	mutex        lock.RWMutex
	lastLifesign map[string]time.Time
	firstRun     time.Time
	timeout      time.Duration
}

// NewIdentityHeartbeatStore returns a new identity heartbeat store
func NewIdentityHeartbeatStore(timeout time.Duration) *IdentityHeartbeatStore {
	i := &IdentityHeartbeatStore{
		timeout:      timeout,
		lastLifesign: map[string]time.Time{},
		firstRun:     time.Now(),
	}
	return i
}

// MarkAlive marks an identity as alive
func (i *IdentityHeartbeatStore) MarkAlive(identity string, t time.Time) {
	log.WithField("identity", identity).Debug("Marking identity alive")
	i.mutex.Lock()
	i.lastLifesign[identity] = t
	i.mutex.Unlock()
}

// IsAlive returns true if the identity is still alive
func (i *IdentityHeartbeatStore) IsAlive(identity string) bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	lifesign, ok := i.lastLifesign[identity]
	if ok {
		// A lifesign has been recorded, check if the lifesign is older
		// than the stale period
		if time.Since(lifesign) < i.timeout {
			return true
		}
	} else {
		// No lifesign has ever been recorded. If the operator has not
		// been up for longer than the stale period, then the identity
		// is still considered alive
		log.Debugf("No lifesign exists %s > %s", time.Since(i.firstRun), i.timeout)
		if time.Since(i.firstRun) < i.timeout {
			return true
		}
	}

	return false
}

// Delete deletes an identity from the store
func (i *IdentityHeartbeatStore) Delete(identity string) {
	log.WithField("identity", identity).Debug("Deleting identity in heartbeat lifesign table")
	i.mutex.Lock()
	defer i.mutex.Unlock()
	delete(i.lastLifesign, identity)
}

// GC removes all lifesign entries which have exceeded the heartbeat by a large
// amount. This happens when the CiliumIdentity is deleted before the
// CiliumEndpoint that refers to it. In that case, the lifesign entry will
// continue to exist. Remove it once has not been updated for a long time.
func (i *IdentityHeartbeatStore) GC() {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	for identity, lifesign := range i.lastLifesign {
		if time.Since(lifesign) > 10*i.timeout {
			log.WithField("identity", identity).Debug("Removing unused heartbeat entry")
			delete(i.lastLifesign, identity)
		}
	}
}
