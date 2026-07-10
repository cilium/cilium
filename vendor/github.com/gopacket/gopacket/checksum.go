// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

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
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	return csum
}

// FoldChecksum folds a 32 bit checksum as defined in RFC1071.
func FoldChecksum(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
