// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package bpf

import (
	"golang.org/x/sys/unix"
)

// ConfigureResourceLimits configures the memory resource limits for the process to allow
// BPF syscall interactions.
func ConfigureResourceLimits() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}
