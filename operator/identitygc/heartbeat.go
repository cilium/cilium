// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// heartbeatStore keeps track of the heartbeat of identities
type heartbeatStore struct {
	mutex        lock.RWMutex
	lastLifesign map[string]time.Time
	firstRun     time.Time
	timeout      time.Duration
	logger       *slog.Logger
}

// newHeartbeatStore returns a new identity heartbeat store
func newHeartbeatStore(timeout time.Duration, logger *slog.Logger) *heartbeatStore {
	i := &heartbeatStore{
		timeout:      timeout,
		lastLifesign: map[string]time.Time{},
		firstRun:     time.Now(),
		logger:       logger.With(logfields.LogSubsys, "identity-heartbeat"),
	}
	return i
}

// markAlive marks an identity as alive
func (i *heartbeatStore) markAlive(identity string, t time.Time) {
	i.logger.Debug("Marking identity alive", logfields.Identity, identity)
	i.mutex.Lock()
	i.lastLifesign[identity] = t
	i.mutex.Unlock()
}

// isAlive returns true if the identity is still alive
func (i *heartbeatStore) isAlive(identity string) bool {
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
		i.logger.Debug(fmt.Sprintf("No lifesign exists %s > %s", time.Since(i.firstRun), i.timeout))
		if time.Since(i.firstRun) < i.timeout {
			return true
		}
	}

	return false
}

// delete deletes an identity from the store
func (i *heartbeatStore) delete(identity string) {
	i.logger.Debug("Deleting identity in heartbeat lifesign table", logfields.Identity, identity)
	i.mutex.Lock()
	defer i.mutex.Unlock()
	delete(i.lastLifesign, identity)
}

// gc removes all lifesign entries which have exceeded the heartbeat by a large
// amount. This happens when the CiliumIdentity is deleted before the
// CiliumEndpoint that refers to it. In that case, the lifesign entry will
// continue to exist. Remove it once has not been updated for a long time.
func (i *heartbeatStore) gc() {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	for identity, lifesign := range i.lastLifesign {
		if time.Since(lifesign) > 10*i.timeout {
			i.logger.Debug("Removing unused heartbeat entry", logfields.Identity, identity)
			delete(i.lastLifesign, identity)
		}
	}
}
