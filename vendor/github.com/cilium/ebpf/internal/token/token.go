// SPDX-License-Identifier: MIT
// Copyright Cilium Contributors (custom extension for BPF token support)

package token

import "sync/atomic"

// globalTokenFD stores the BPF token file descriptor for use in feature probes.
// -1 means no token is set.
var globalTokenFD atomic.Int32

func init() {
	globalTokenFD.Store(-1)
}

// SetGlobalToken sets the global BPF token file descriptor for feature probes.
// This should be called early during initialization before any feature probes run.
func SetGlobalToken(fd int) {
	globalTokenFD.Store(int32(fd))
}

// GetGlobalToken returns the global BPF token file descriptor, or -1 if not set.
func GetGlobalToken() int {
	return int(globalTokenFD.Load())
}
