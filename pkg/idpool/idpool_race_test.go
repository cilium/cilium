// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build race

package idpool

import (
	"testing"
)

// TestAllocateID without the race detection enabled is too slow to run with
// race detector set. Thus, we need to put it in a separate file so the unit
// tests don't time out while running with race detector by having a lower
// number of parallel goroutines than it would have been if we ran it without
// the race detector.
func TestAllocateID(t *testing.T) {
	testAllocatedID(t, 5)
}
