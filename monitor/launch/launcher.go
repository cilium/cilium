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
	"fmt"
	"os"
	"os/exec"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"

	log "github.com/sirupsen/logrus"
)

const targetName = "cilium-node-monitor"

// NodeMonitor is used to wrap the node executable binary.
type NodeMonitor struct {
	mutex   lock.RWMutex
	arg     string
	process *os.Process
	state   *models.MonitorStatus
}

// Run starts the node monitor.
func (nm *NodeMonitor) Run() {
	for {
		cmd := exec.Command(targetName, nm.GetArg())
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			cmdStr := fmt.Sprintf("%s %s", targetName, nm.GetArg())
			log.WithError(err).WithField("cmd", cmdStr).Error("cmd.Start()")
		}

		nm.setProcess(cmd.Process)

		r := bufio.NewReader(stdout)
		for nm.getProcess() != nil {
			l, _ := r.ReadBytes('\n')
			var tmp *models.MonitorStatus
			if err := json.Unmarshal(l, &tmp); err != nil {
				continue
			}
			nm.setState(tmp)
		}
	}
}

// Restart stops the node monitor which will trigger a rerun.
func (nm *NodeMonitor) Restart(arg string) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	nm.arg = arg

	if nm.process == nil {
		return
	}
	if err := nm.process.Kill(); err != nil {
		log.WithError(err).WithField("pid", nm.process.Pid).Error("process.Kill()")
	}
	nm.process = nil
}

// State returns the monitor status.
func (nm *NodeMonitor) State() *models.MonitorStatus {
	nm.mutex.RLock()
	state := nm.state
	nm.mutex.RUnlock()
	return state
}

// GetArg returns the NodeMonitor arg.
func (nm *NodeMonitor) GetArg() string {
	nm.mutex.RLock()
	arg := nm.arg
	nm.mutex.RUnlock()
	return arg
}

// setProcess sets the internal node monitor process with the given process.
func (nm *NodeMonitor) setProcess(proc *os.Process) {
	nm.mutex.Lock()
	nm.process = proc
	nm.mutex.Unlock()
}

// getProcess returns the NodeMonitor internal process.
func (nm *NodeMonitor) getProcess() *os.Process {
	nm.mutex.RLock()
	proc := nm.process
	nm.mutex.RUnlock()
	return proc
}

// setProcess sets the internal state monitor with the given state.
func (nm *NodeMonitor) setState(state *models.MonitorStatus) {
	nm.mutex.Lock()
	nm.state = state
	nm.mutex.Unlock()
}
