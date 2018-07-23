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

package pidfile

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "pidfile")

// Write the pid of the process to the specified path, and attach a cleanup
// handler to the exit of the program so it's removed afterwards.
func Write(path string) error {
	pid := os.Getpid()
	pidBytes := []byte(strconv.Itoa(pid) + "\n")
	if err := ioutil.WriteFile(path, pidBytes, 0660); err != nil {
		return err
	}

	// Handle the cleanup
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		for s := range sig {
			log.WithField("signal", s).Info("Exiting due to signal")
			os.Remove(path)
			os.Exit(0)
		}
	}()

	return nil
}

// kill parses the PID in the provided slice and attempts to kill the process
// associated with that PID.
func kill(buf []byte) error {
	pidStr := strings.TrimSpace(string(buf))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("Failed to parse pid from %q: %s", pidStr, err)
	}
	oldProc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("Could not find process %d: %s", pid, err)
	}
	// According to the golang/pkg/os documentation:
	// "On Unix systems, FindProcess always succeeds and returns a Process
	// for the given pid, regardless of whether the process exists."
	//
	// It could return "os: process already finished", so just log it at
	// a low level and ignore the error.
	if err := oldProc.Kill(); err != nil {
		log.WithError(err).Debug("Ignoring process kill failure")
	}
	if err := oldProc.Release(); err != nil {
		return fmt.Errorf("Couldn't release process %d: %s", pid, err)
	}
	return nil
}

// Kill opens the pidfile at the specified path, attempts to read the PID and
// kill the process represented by that PID. If the file doesn't exist, the
// corresponding process doesn't exist, or the process is successfully killed,
// returns nil. Otherwise, returns an error indicating the failure to kill the
// process.
//
// On success, deletes the pidfile from the filesystem. Otherwise, leaves it
// in place.
func Kill(pidfilePath string) error {
	if _, err := os.Stat(pidfilePath); os.IsNotExist(err) {
		return nil
	}

	pidfile, err := ioutil.ReadFile(pidfilePath)
	if err != nil {
		return err
	}

	if err := kill(pidfile); err != nil {
		return err
	}

	return os.RemoveAll(pidfilePath)
}
