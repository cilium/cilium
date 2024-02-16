// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

// CacheStatus allows waiting for k8s caches to synchronize.
type CacheStatus chan struct{}

// Sychronized returns true if caches have been synchronized at least once.
//
// Returns true for an uninitialized [CacheStatus].
func (cs CacheStatus) Synchronized() bool {
	if cs == nil {
		return true
	}

	select {
	case <-cs:
		return true
	default:
		return false
	}
}
