// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package launcher

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "launcher")

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
	cmdStr := fmt.Sprintf("%s %s", targetName, launcher.GetArgs())
	cmd := exec.Command(targetName, launcher.GetArgs()...)
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		log.WithError(err).WithField("cmd", cmdStr).Error("cmd.Start()")
		return fmt.Errorf("unable to launch process %s: %s", cmdStr, err)
	}

	launcher.setProcess(cmd.Process)
	launcher.setStdout(stdout)

	// Wait for the process to exit in the background to release all
	// resources
	go func() {
		err := cmd.Wait()
		log.WithFields(logrus.Fields{
			"exitCode": err,
			"cmd":      cmdStr,
		}).Debug("Process exited")
	}()

	return nil
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
