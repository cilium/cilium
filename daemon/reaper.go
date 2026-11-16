// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// startReaper installs a SIGCHLD handler and reaps child processes in the
// background. This prevents zombie processes from accumulating when the
// daemon spawns (and later replaces) child processes.
func startReaper() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGCHLD)

	go func() {
		reap()
		for range sigCh {
			reap()
		}
	}()
}

// reap reaps all currently terminated child processes without blocking.
func reap() {
	var ws unix.WaitStatus
	for {
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if err == unix.EINTR {
			continue
		}
		if pid <= 0 {
			break
		}
	}
}
