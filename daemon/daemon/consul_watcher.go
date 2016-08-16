//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"time"

	"github.com/cilium/cilium/common"

	consulAPI "github.com/hashicorp/consul/api"
)

// EnableConsulWatcher watches for consul changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) EnableConsulWatcher(maxSeconds time.Duration) {
	go func() {
		curSeconds := time.Second
		var (
			k   *consulAPI.KVPair
			q   *consulAPI.QueryMeta
			qo  consulAPI.QueryOptions
			err error
		)
		for {
			k, q, err = d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
			if err != nil {
				log.Errorf("Unable to retreive last free Index: %s", err)
			}
			if k != nil {
				break
			} else {
				log.Debugf("Unable to retreive last free Index, please start some containers with labels.")
			}
			time.Sleep(maxSeconds)
		}

		for {
			k, q, err = d.consul.KV().Get(common.LastFreeIDKeyPath, &qo)
			if err != nil {
				log.Errorf("Unable to retreive last free Index: %s", err)
			}
			if k == nil || q == nil {
				log.Warning("Unable to retreive last free Index, please start some containers with labels.")
				time.Sleep(curSeconds)
				if curSeconds < maxSeconds {
					curSeconds += time.Second
				}
				continue
			}
			curSeconds = time.Second
			qo.WaitIndex = q.LastIndex
			go func() {
				d.triggerPolicyUpdates([]uint32{})
			}()
		}
	}()
}
