// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// Copyright The Kubernetes Authors.

package allocator

import (
	"math/big"
	"math/bits"
)

// countBits returns the number of set bits in n
func countBits(n *big.Int) int {
	var count int = 0
	for _, w := range n.Bits() {
		count += bits.OnesCount64(uint64(w))
	}
	return count
}
