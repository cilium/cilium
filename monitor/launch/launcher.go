// Copyright 2017 Authors of Cilium
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

package launch

import (
	"bufio"
	"encoding/json"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/launcher"
)

const targetName = "cilium-node-monitor"

// NodeMonitor is used to wrap the node executable binary.
type NodeMonitor struct {
	launcher.Launcher

	state *models.MonitorStatus
}

// Run starts the node monitor.
func (nm *NodeMonitor) Run() {
	nm.SetTarget(targetName)
	for {
		nm.Launcher.Run()

		r := bufio.NewReader(nm.GetStdout())
		for nm.GetProcess() != nil {
			l, _ := r.ReadBytes('\n')
			var tmp *models.MonitorStatus
			if err := json.Unmarshal(l, &tmp); err != nil {
				continue
			}
			nm.setState(tmp)
		}
	}
}

// State returns the monitor status.
func (nm *NodeMonitor) State() *models.MonitorStatus {
	nm.Mutex.RLock()
	state := nm.state
	nm.Mutex.RUnlock()
	return state
}

// setState sets the internal state monitor with the given state.
func (nm *NodeMonitor) setState(state *models.MonitorStatus) {
	nm.Mutex.Lock()
	nm.state = state
	nm.Mutex.Unlock()
}
