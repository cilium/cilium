// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package math

// MSB returns the position of most significant bit for the given uint64
func MSB(x uint64) uint8 {
	var i uint8
	for ; (x >> i) != 0; i++ {
	}
	return i
}

// GetMask returns a bit mask filled with ones of length 'x'.
// e.g.:
// GetMask(3) => 0b00000111
// GetMask(4) => 0b00001111
// GetMask(5) => 0x00011111
func GetMask(x uint8) uint64 {
	return ^uint64(0) >> (64 - x)
}
