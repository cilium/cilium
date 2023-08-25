// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package math

// IntMin returns the minimum integer provided
func IntMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IntMax returns the maximum integer provided
func IntMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
