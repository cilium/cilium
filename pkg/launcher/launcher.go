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

package launcher

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

// Launcher is used to wrap the node executable binary.
type Launcher struct {
	Mutex   lock.RWMutex
	target  string
	args    []string
	process *os.Process
	stdout  io.ReadCloser
}

// Run starts the daemon.
func (launcher *Launcher) Run() error {
	targetName := launcher.GetTarget()
	cmd := exec.Command(targetName, launcher.GetArgs()...)
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		cmdStr := fmt.Sprintf("%s %s", targetName, launcher.GetArgs())
		log.WithError(err).WithField("cmd", cmdStr).Error("cmd.Start()")
		return fmt.Errorf("unable to launch process %s: %s", cmdStr, err)
	}

	launcher.setProcess(cmd.Process)
	launcher.setStdout(stdout)

	return nil
}

// Restart stops the launcher which will trigger a rerun.
func (launcher *Launcher) Restart(args []string) {
	launcher.Mutex.Lock()
	defer launcher.Mutex.Unlock()
	launcher.args = args

	if launcher.process == nil {
		return
	}
	if err := launcher.process.Kill(); err != nil {
		log.WithError(err).WithField("pid", launcher.process.Pid).Error("process.Kill()")
	}
	launcher.process = nil
}

// SetTarget sets the Launcher target.
func (launcher *Launcher) SetTarget(target string) {
	launcher.Mutex.Lock()
	launcher.target = target
	launcher.Mutex.Unlock()
}

// GetTarget returns the Launcher target.
func (launcher *Launcher) GetTarget() string {
	launcher.Mutex.RLock()
	arg := launcher.target
	launcher.Mutex.RUnlock()
	return arg
}

// SetArgs sets the Launcher arg.
func (launcher *Launcher) SetArgs(args []string) {
	launcher.Mutex.Lock()
	launcher.args = args
	launcher.Mutex.Unlock()
}

// GetArgs returns the Launcher arg.
func (launcher *Launcher) GetArgs() []string {
	launcher.Mutex.RLock()
	args := launcher.args
	launcher.Mutex.RUnlock()
	return args
}

// setProcess sets the internal process with the given process.
func (launcher *Launcher) setProcess(proc *os.Process) {
	launcher.Mutex.Lock()
	launcher.process = proc
	launcher.Mutex.Unlock()
}

// GetProcess returns the internal process.
func (launcher *Launcher) GetProcess() *os.Process {
	launcher.Mutex.RLock()
	proc := launcher.process
	launcher.Mutex.RUnlock()
	return proc
}

// setStdout sets the stdout pipe.
func (launcher *Launcher) setStdout(stdout io.ReadCloser) {
	launcher.Mutex.Lock()
	launcher.stdout = stdout
	launcher.Mutex.Unlock()
}

// GetStdout gets the stdout pipe.
func (launcher *Launcher) GetStdout() io.ReadCloser {
	launcher.Mutex.RLock()
	stdout := launcher.stdout
	launcher.Mutex.RUnlock()
	return stdout
}
