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
	"os"
	"os/exec"

	"github.com/cilium/cilium/api/v1/models"

	log "github.com/sirupsen/logrus"
)

const targetName = "cilium-node-monitor"

// NodeMonitor is used to wrap the node executable binary.
type NodeMonitor struct {
	Arg     string
	process *os.Process
	state   *models.MonitorStatus
}

// Run starts the node monitor.
func (nm *NodeMonitor) Run() {
	for {
		cmd := exec.Command(targetName, nm.Arg)
		stdout, _ := cmd.StdoutPipe()

		if err := cmd.Start(); err != nil {
			log.Errorf("cmd.Start(): %s", err)
		}
		nm.process = cmd.Process

		r := bufio.NewReader(stdout)
		for nm.process != nil {
			l, _ := r.ReadBytes('\n')
			var tmp *models.MonitorStatus
			if err := json.Unmarshal(l, &tmp); err != nil {
				continue
			}
			nm.state = tmp
		}
	}
}

// Restart stops the node monitor which will trigger a rerun.
func (nm *NodeMonitor) Restart(arg string) {
	nm.Arg = arg

	if nm.process == nil {
		return
	}
	if err := nm.process.Kill(); err != nil {
		log.Errorf("process.Kill(): %s", err)
	}
	nm.process = nil
}

// State returns the monitor status.
func (nm *NodeMonitor) State() *models.MonitorStatus {
	return nm.state
}
