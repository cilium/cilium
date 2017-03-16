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
)

// EnableKVStoreWatcher watches for kvstore changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) EnableKVStoreWatcher(maxSeconds time.Duration) {
	ch := d.kvClient.GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
	go func() {
		for {
			select {
			case updates, update_ok := <-ch:
				if !update_ok {
					log.Debugf("Watcher for %s closed, reacquiring it", common.LastFreeLabelIDKeyPath)
					ch = d.kvClient.GetWatcher(common.LastFreeLabelIDKeyPath, maxSeconds)
				}
				d.triggerPolicyUpdates(updates)
			}
		}
	}()
}
