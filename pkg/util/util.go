// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package util

// RoundUp rounds x up to the next specified multiple. This implementation
// is equivalent to the kernel's roundup().
func RoundUp(x, multiple int) int {
	return int(((x + (multiple - 1)) / multiple) * multiple)
}

// RoundDown rounds x down to the next specified multiple. Again, this
// implementation is equivalent to the kernel's rounddown().
func RoundDown(x, multiple int) int {
	return int(x - (x % multiple))
}
