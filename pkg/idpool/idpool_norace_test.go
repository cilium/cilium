// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !race

package idpool

import (
	"testing"
)

func TestAllocateID(t *testing.T) {
	testAllocatedID(t, 256)
}
