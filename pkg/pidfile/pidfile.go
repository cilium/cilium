// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pidfile

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/cleanup"
)

var (
	cleanUPSig = make(chan struct{})
	cleanUPWg  = &sync.WaitGroup{}
)

// Remove deletes the pidfile at the specified path. This does not clean up
// the corresponding process, so should only be used when it is known that the
// PID contained in the file at the specified path is no longer running.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func write(path string, pid int) error {
	pidBytes := []byte(strconv.Itoa(pid) + "\n")
	if err := os.WriteFile(path, pidBytes, 0660); err != nil {
		return err
	}

	cleanup.DeferTerminationCleanupFunction(cleanUPWg, cleanUPSig, func() {
		Remove(path)
	})

	return nil
}

// Write the pid of the process to the specified path, and attach a cleanup
// handler to the exit of the program so it's removed afterwards.
func Write(path string) error {
	pid := os.Getpid()
	return write(path, pid)
}

// Clean cleans up everything created by this package.
func Clean() {
	close(cleanUPSig)
	cleanUPWg.Wait()

	// Reset to original state for reuse in tests
	cleanUPSig = make(chan struct{})
	cleanUPWg = &sync.WaitGroup{}
}

// kill parses the PID in the provided slice and attempts to kill the process
// associated with that PID.
func kill(buf []byte, pidfile string) (int, error) {
	pidStr := strings.TrimSpace(string(buf))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse pid from %q: %s", pidStr, err)
	}
	oldProc, err := os.FindProcess(pid)
	if err != nil {
		return 0, fmt.Errorf("could not find process %d: %s", pid, err)
	}
	// According to the golang/pkg/os documentation:
	// "On Unix systems, FindProcess always succeeds and returns a Process
	// for the given pid, regardless of whether the process exists."
	//
	// It could return "os: process already finished", therefore we ignore
	// the error, but return pid 0 to indicate that the process was not
	// killed.
	if err := oldProc.Kill(); err != nil {
		// return pid 0 after releasing process
		pid = 0
	}
	if err := oldProc.Release(); err != nil {
		return 0, fmt.Errorf("couldn't release process %d: %s", pid, err)
	}
	return pid, nil
}

// Kill opens the pidfile at the specified path, attempts to read the PID and
// kill the process represented by that PID. If the file doesn't exist, the
// corresponding process doesn't exist, or the process is successfully killed,
// reports no error and returns the pid of the killed process (if no process
// was killed, returns pid 0). Otherwise, returns an error indicating the
// failure to kill the process.
//
// On success, deletes the pidfile from the filesystem. Otherwise, leaves it
// in place.
func Kill(pidfilePath string) (int, error) {
	if _, err := os.Stat(pidfilePath); os.IsNotExist(err) {
		return 0, nil
	}

	pidfile, err := os.ReadFile(pidfilePath)
	if err != nil {
		return 0, err
	}

	pid, err := kill(pidfile, pidfilePath)
	if err != nil {
		return pid, err
	}

	return pid, Remove(pidfilePath)
}
