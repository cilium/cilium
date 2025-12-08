package policymap

import (
	"sort"
	"testing"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/stretchr/testify/require"
)

// TestRuleSorting verifies that rules are sorted in the order expected by BPF.
func TestRuleSorting(t *testing.T) {
	// Sorted by derived value:
	// 1. 256  (1)
	// 2. 80   (20480)
	// 3. 8080 (36895)
	// 4. 443  (47873)

	type rule struct {
		Port uint16
	}

	rules := []rule{
		{Port: 80},
		{Port: 256},
		{Port: 443},
		{Port: 8080},
	}

	// Sort using the proposed logic (NBO)
	sort.Slice(rules, func(i, j int) bool {
		pi := byteorder.HostToNetwork16(rules[i].Port)
		pj := byteorder.HostToNetwork16(rules[j].Port)
		return pi < pj
	})

	expected := []uint16{256, 80, 8080, 443}
	got := make([]uint16, len(rules))
	for i, r := range rules {
		got[i] = r.Port
	}

	require.Equal(t, expected, got, "Sorting order should match BPF NBO expectations")
}

// Helper to confirm byte swapping behavior on this platform
func TestByteSwap(t *testing.T) {
	val := uint16(256) // 0x0100
	swapped := byteorder.HostToNetwork16(val)

	// Assuming running on x86 (LE).
	if isLittleEndian() {
		require.Equal(t, uint16(1), swapped)
	} else {
		require.Equal(t, uint16(256), swapped)
	}
}

func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	return (b == 0x04)
}
