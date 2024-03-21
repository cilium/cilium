// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

type DummyOwner struct {
	updated chan identity.NumericIdentity
	mutex   lock.Mutex
	cache   IdentityCache
}

func NewDummyOwner() *DummyOwner {
	return &DummyOwner{
		cache:   IdentityCache{},
		updated: make(chan identity.NumericIdentity, 1024),
	}
}

func (d *DummyOwner) UpdateIdentities(added, deleted IdentityCache) {
	d.mutex.Lock()
	log.Debugf("Dummy UpdateIdentities(added: %v, deleted: %v)", added, deleted)
	for id, lbls := range added {
		d.cache[id] = lbls
		d.updated <- id
	}
	for id := range deleted {
		delete(d.cache, id)
		d.updated <- id
	}
	d.mutex.Unlock()
}

func (d *DummyOwner) GetIdentity(id identity.NumericIdentity) labels.LabelArray {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.cache[id]
}

func (d *DummyOwner) GetNodeSuffix() string {
	return "foo"
}

// WaitUntilID waits until an update event is received for the
// 'target' identity and returns the number of events processed to get
// there. Returns 0 in case of 'd.updated' channel is closed or
// nothing is received from that channel in 60 seconds.
func (d *DummyOwner) WaitUntilID(target identity.NumericIdentity) int {
	rounds := 0
	timer, timerDone := inctimer.New()
	defer timerDone()
	for {
		select {
		case nid, ok := <-d.updated:
			if !ok {
				// updates channel closed
				return 0
			}
			rounds++
			if nid == target {
				return rounds
			}
		case <-timer.After(60 * time.Second):
			// Timed out waiting for KV-store events
			return 0
		}
	}
}
