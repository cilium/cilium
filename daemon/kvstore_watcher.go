// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"

	log "github.com/sirupsen/logrus"
)

// EnableKVStoreWatcher watches for kvstore changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) EnableKVStoreWatcher(maxSeconds time.Duration) {
	if maxID, err := GetMaxLabelID(); err == nil {
		d.setCachedMaxLabelID(maxID)
	}
	ch := kvstore.Client().GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
	go func() {
		for {
			select {
			case updates, updateOk := <-ch:
				if !updateOk {
					log.WithField(logfields.Path, common.LastFreeLabelIDKeyPath).Debug("Watcher for path closed, reacquiring it")
					ch = kvstore.Client().GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
				}
				if len(updates) != 0 {
					d.setCachedMaxLabelID(updates[0])
				}
				d.TriggerPolicyUpdates(updates)
			}
		}
	}()
}

// GetCachedMaxLabelID returns the cached max label ID from the last event
// received from the KVStore.
func (d *Daemon) GetCachedMaxLabelID() (policy.NumericIdentity, error) {
	d.maxCachedLabelIDMU.RLock()
	id := d.maxCachedLabelID
	d.maxCachedLabelIDMU.RUnlock()
	if id == 0 {
		// FIXME: KVStore might not set up the watcher at this point
		// If that's the case, we should ask directly the KVStore
		// What's the maxLabelID value.
		return policy.MinimalNumericIdentity, nil
	}
	return id, nil
}

func (d *Daemon) setCachedMaxLabelID(id policy.NumericIdentity) {
	d.maxCachedLabelIDMU.Lock()
	d.maxCachedLabelID = id
	d.maxCachedLabelIDMU.Unlock()
}
