// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"math"
	"math/bits"
)

// MaskedPort is a port with a wild card mask value.
// The port range is represented by a masked port
// because we need to use masks for policy Keys
// that are indexed in the datapath by a bitwise
// longest-prefix-match trie.
type MaskedPort struct {
	port uint16
	mask uint16
}

func (m MaskedPort) String() string {
	return fmt.Sprintf("{port: 0x%x, mask: 0x%x}", m.port, m.mask)
}

// maskedPort returns a new MaskedPort where 'wildcardBits' lowest bits are wildcarded.
func maskedPort(port uint16, wildcardBits int) MaskedPort {
	mask := uint16(math.MaxUint16) << wildcardBits
	return MaskedPort{port & mask, mask}
}

// PortRangeToMaskedPorts returns a slice of masked ports for the given port range.
// If the end port is equal to or less then the start port than the start port is returned,
// as a fully masked port.
// Ports are not returned in any particular order, so testing code needs to sort them
// for consistency.
func PortRangeToMaskedPorts(start uint16, end uint16) (ports []MaskedPort) {
	// This is a wildcard.
	if start == 0 && (end == 0 || end == math.MaxUint16) {
		return []MaskedPort{{0, 0}}
	}
	// This is a single port.
	if end <= start {
		return []MaskedPort{{start, 0xffff}}
	}
	// Find the number of common leading bits. The first uncommon bit will be 0 for the start
	// and 1 for the end.
	commonBits := bits.LeadingZeros16(start ^ end)

	// Cover the case where all the bits after the common bits are zeros on start and ones on
	// end. In this case the range can be represented by a single masked port instead of two
	// that would be produced below.
	// For example, if the range is from 16-31 (0b10000 - 0b11111), then we return 0b1xxxx
	// instead of 0b10xxx and 0b11xxx that would be produced when approaching the middle from
	// the two sides.
	//
	// This also covers the trivial case where all the bits are in common (i.e., start == end).
	mask := uint16(math.MaxUint16) >> commonBits
	if start&mask == 0 && ^end&mask == 0 {
		return []MaskedPort{maskedPort(start, 16-commonBits)}
	}

	// Find the "middle point" toward which the masked ports approach from both sides.
	// This "middle point" is the highest bit that differs between the range start and end.
	middleBit := 16 - 1 - commonBits
	middle := uint16(1 << middleBit)

	// Wildcard the trailing zeroes to the right of the middle bit of the range start.
	// This covers the values immediately following the port range start, including the start itself.
	// The middle bit is added to avoid counting zeroes past it.
	bit := bits.TrailingZeros16(start | middle)
	ports = append(ports, maskedPort(start, bit))

	// Find all 0-bits between the trailing zeroes and the middle bit and add MaskedPorts where
	// each found 0-bit is set and the lower bits are wildcarded. This covers the range from the
	// start to the middle not covered by the trailing zeroes above.
	// The current 'bit' is skipped since we know it is 1.
	for bit++; bit < middleBit; bit++ {
		if start&(1<<bit) == 0 {
			// Adding 1<<bit will set the bit since we know it is not set
			ports = append(ports, maskedPort(start+1<<bit, bit))
		}
	}

	// Wildcard the trailing ones to the right of the middle bit of the range end.
	// This covers the values immediately preceding and including the range end.
	// The middle bit is added to avoid counting ones past it.
	bit = bits.TrailingZeros16(^end | middle)
	ports = append(ports, maskedPort(end, bit))

	// Find all 1-bits between the trailing ones and the middle bit and add MaskedPorts where
	// each found 1-bit is cleared and the lower bits are wildcarded. This covers the range from
	// the end to the middle not covered by the trailing ones above.
	// The current 'bit' is skipped since we know it is 0.
	for bit++; bit < middleBit; bit++ {
		if end&(1<<bit) != 0 {
			// Subtracting 1<<bit will clear the bit since we know it is set
			ports = append(ports, maskedPort(end-1<<bit, bit))
		}
	}

	return ports
}
