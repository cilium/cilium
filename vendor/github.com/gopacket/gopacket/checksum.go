// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import "math"

// ChecksumVerificationResult provides information about a checksum verification.
// The checksums are represented using uint32 to fit even the largest checksums.
// If a checksum is optional and unset, Correct and Actual might mismatch even
// though Valid is true. In this case, Correct is the computed optional checksum
// and Actual is 0.
type ChecksumVerificationResult struct {
	// Valid tells whether the checksum verification succeeded.
	Valid bool
	// Correct is the correct checksum that was expected to be found.
	Correct uint32
	// Actual is the checksum that was found and which might be wrong.
	Actual uint32
}

// ChecksumMismatch provides information about a failed checksum verification
// for a layer.
type ChecksumMismatch struct {
	ChecksumVerificationResult
	// Layer is the layer whose checksum is invalid.
	Layer Layer
	// LayerIndex is the index of the layer in the packet.
	LayerIndex int
}

// ComputeChecksum computes the internet checksum as defined in RFC1071. The
// passed-in csum is any initial checksum data that's already been computed.
func ComputeChecksum(data []byte, csum uint32) uint32 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	// Sum in 64 bits: the words of more than 128 KiB of data, which an IPv6
	// jumbogram can carry, add up to more than 32 bits, and the carry out
	// of bit 31 would be lost.
	sum := uint64(csum)
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		sum += uint64(data[i]) << 8
		sum += uint64(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint64(data[length]) << 8
	}
	if sum > math.MaxUint32 {
		// Fold the sum so that it fits the 32-bit result. Adding 0xffff,
		// which is zero in one's complement arithmetic, keeps the result at
		// least as large as any word that was summed, so that callers can
		// still subtract the checksum found in the data before folding.
		for sum > 0xffff {
			sum = (sum >> 16) + (sum & 0xffff)
		}
		sum += 0xffff
	}
	return uint32(sum)
}

// FoldChecksum folds a 32 bit checksum as defined in RFC1071.
func FoldChecksum(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
