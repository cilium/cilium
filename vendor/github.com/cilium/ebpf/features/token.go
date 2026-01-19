// SPDX-License-Identifier: MIT
// Copyright Cilium Contributors (custom extension for BPF token support)

package features

import (
	"github.com/cilium/ebpf/internal/token"
)

// SetGlobalToken sets the global BPF token file descriptor for feature probes.
// This should be called early during initialization before any feature probes run.
func SetGlobalToken(fd int) {
	token.SetGlobalToken(fd)
}

// GetGlobalToken returns the global BPF token file descriptor, or -1 if not set.
func GetGlobalToken() int {
	return token.GetGlobalToken()
}
