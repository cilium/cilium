// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// maskedPorts have to be sorted for this check
func validateMaskedPorts(t *testing.T, maskedPorts []MaskedPort, start, end uint16) {
	// Wildcard case.
	if start == 0 && end == 0 {
		require.Len(t, maskedPorts, 1)
		require.Equal(t, uint16(0), maskedPorts[0].port)
		require.Equal(t, uint16(0), maskedPorts[0].mask)
		return
	}
	require.NotNil(t, maskedPorts)
	require.NotEmpty(t, maskedPorts)
	// validate that range elements are continuous and non-overlapping
	first := maskedPorts[0].port
	last := first + ^maskedPorts[0].mask
	for i := 1; i < len(maskedPorts); i++ {
		require.Equal(t, maskedPorts[i].port, last+1)
		last = maskedPorts[i].port + ^maskedPorts[i].mask
	}
	// Check that the computed range matches the given range
	require.Equal(t, first, start)
	require.Equal(t, last, end)
}

func TestPortRange(t *testing.T) {
	type testCase struct {
		start, end uint16
		expected   []MaskedPort
	}

	testCases := []testCase{
		// worst case test
		{
			start: 1,
			end:   65534,
			expected: []MaskedPort{
				{port: 0x1, mask: 0xffff},    // 1
				{port: 0x2, mask: 0xfffe},    // 2-3
				{port: 0x4, mask: 0xfffc},    // 4-7
				{port: 0x8, mask: 0xfff8},    // 8-15
				{port: 0x10, mask: 0xfff0},   // 16-31
				{port: 0x20, mask: 0xffe0},   // 32-63
				{port: 0x40, mask: 0xffc0},   // 64-127
				{port: 0x80, mask: 0xff80},   // 128-255
				{port: 0x100, mask: 0xff00},  // 256-511
				{port: 0x200, mask: 0xfe00},  // 512-1023
				{port: 0x400, mask: 0xfc00},  // 1024-2047
				{port: 0x800, mask: 0xf800},  // 2048-4095
				{port: 0x1000, mask: 0xf000}, // 4096-8191
				{port: 0x2000, mask: 0xe000}, // 8192-16383
				{port: 0x4000, mask: 0xc000}, // 16384-32767
				{port: 0x8000, mask: 0xc000}, // 32768-49151
				{port: 0xc000, mask: 0xe000}, // 49152-57343
				{port: 0xe000, mask: 0xf000}, // 57344-61439
				{port: 0xf000, mask: 0xf800}, // 61440-63487
				{port: 0xf800, mask: 0xfc00}, // 63488-64511
				{port: 0xfc00, mask: 0xfe00}, // 64512-65023
				{port: 0xfe00, mask: 0xff00}, // 65024-65279
				{port: 0xff00, mask: 0xff80}, // 65280-65407
				{port: 0xff80, mask: 0xffc0}, // 65408-65471
				{port: 0xffc0, mask: 0xffe0}, // 65472-65503
				{port: 0xffe0, mask: 0xfff0}, // 65504-65519
				{port: 0xfff0, mask: 0xfff8}, // 65520-65527
				{port: 0xfff8, mask: 0xfffc}, // 65528-65531
				{port: 0xfffc, mask: 0xfffe}, // 65532-65533
				{port: 0xfffe, mask: 0xffff}, // 65534
			},
		},
		{
			start: 1,
			end:   1023,
			expected: []MaskedPort{
				{port: 0x1, mask: 0xffff},   // 1
				{port: 0x2, mask: 0xfffe},   // 2-3
				{port: 0x4, mask: 0xfffc},   // 4-7
				{port: 0x8, mask: 0xfff8},   // 8-15
				{port: 0x10, mask: 0xfff0},  // 16-31
				{port: 0x20, mask: 0xffe0},  // 32-63
				{port: 0x40, mask: 0xffc0},  // 64-127
				{port: 0x80, mask: 0xff80},  // 128-255
				{port: 0x100, mask: 0xff00}, // 256-511
				{port: 0x200, mask: 0xfe00}, // 512-1023
			},
		},
		{
			start: 0,
			end:   1023,
			expected: []MaskedPort{
				{port: 0, mask: 0xfc00}, // 0-1023
			},
		},
		// A typical large case test
		{
			start: 1024,
			end:   65535,
			expected: []MaskedPort{
				{port: 0x400, mask: 0xfc00},  // 1024-2047
				{port: 0x800, mask: 0xf800},  // 2048-4095
				{port: 0x1000, mask: 0xf000}, // 4096-8191
				{port: 0x2000, mask: 0xe000}, // 8192-16383
				{port: 0x4000, mask: 0xc000}, // 16384-32767
				{port: 0x8000, mask: 0x8000}, // 32768-65535
			},
		},
		// Another typical large case test
		{
			start: 10000,
			end:   20000,
			expected: []MaskedPort{
				{port: 0x2710, mask: 0xfff0}, // 10000 - 10015
				{port: 0x2720, mask: 0xffe0}, // 10016 - 10047
				{port: 0x2740, mask: 0xffc0}, // 10048 - 10111
				{port: 0x2780, mask: 0xff80}, // 10112 - 10239
				{port: 0x2800, mask: 0xf800}, // 10240 - 12287
				{port: 0x3000, mask: 0xf000}, // 12288 - 16383
				{port: 0x4000, mask: 0xf800}, // 16384 - 18431
				{port: 0x4800, mask: 0xfc00}, // 18432 - 19455
				{port: 0x4c00, mask: 0xfe00}, // 19456 - 19967
				{port: 0x4e00, mask: 0xffe0}, // 19968 - 19999
				{port: 0x4e20, mask: 0xffff}, // 20000
			},
		},
		{
			start: 1000,
			end:   1999,
			expected: []MaskedPort{
				{port: 0x3e8, mask: 0xfff8},
				{port: 0x3f0, mask: 0xfff0},
				{port: 0x400, mask: 0xfe00},
				{port: 0x600, mask: 0xff00},
				{port: 0x700, mask: 0xff80},
				{port: 0x780, mask: 0xffc0},
				{port: 0x7c0, mask: 0xfff0},
			},
		},
		{
			start: 0,
			end:   1,
			expected: []MaskedPort{
				{port: 0, mask: 0xfffe}, // 0-1
			},
		},
		{
			start: 16,
			end:   31,
			expected: []MaskedPort{
				{port: 0x10, mask: 0xfff0}, // 16-31
			},
		},
		{
			start: 0xff00, // 65280
			end:   0xffff, // 65535
			expected: []MaskedPort{
				{port: 0xff00, mask: 0xff00}, // 65280-65535
			},
		},
		{
			start: 0,
			end:   0xffff,
			expected: []MaskedPort{
				{port: 0x0, mask: 0x0000}, // 0-0xffff
			},
		},
		{
			start: 1,
			end:   7,
			expected: []MaskedPort{
				{port: 0x1, mask: 0xffff}, // 1
				{port: 0x2, mask: 0xfffe}, // 2-3
				{port: 0x4, mask: 0xfffc}, // 4-7
			},
		},
		{
			start: 0,
			end:   7,
			expected: []MaskedPort{
				{port: 0x0, mask: 0xfff8}, // 0-7
			},
		},
		{
			start: 5,
			end:   10,
			expected: []MaskedPort{
				{0b0000000000000101, 0b1111111111111111}, // 5
				{0b0000000000000110, 0b1111111111111110}, // 6-7
				{0b0000000000001000, 0b1111111111111110}, // 8-9
				{0b0000000000001010, 0b1111111111111111}, // 10
			},
		},
		{
			start: 0,
			end:   16,
			expected: []MaskedPort{
				{0b0000000000000000, 0b1111111111110000}, // 0xxxx
				{0b0000000000010000, 0b1111111111111111}, // 10000
			},
		},
		{
			start: 0b0000000000010000, // 16
			end:   0b0000000110000111, // 391
			expected: []MaskedPort{
				{0b0000000000010000, 0b1111111111110000}, // 00001xxxx, 16-31
				{0b0000000000100000, 0b1111111111100000}, // 0001xxxxx, 32-63
				{0b0000000001000000, 0b1111111111000000}, // 001xxxxxx, 64-127
				{0b0000000010000000, 0b1111111110000000}, // 01xxxxxxx, 128-255
				{0b0000000100000000, 0b1111111110000000}, // 01xxxxxxx, 256-383
				{0b0000000110000000, 0b1111111111111000}, // 10000000x, 384-391
			},
		},
		{
			start: 22,
			end:   23,
			expected: []MaskedPort{
				{0b0000000000010110, 0b1111111111111110}, // 22-23
			},
		},
		{
			start: 23,
			end:   24,
			expected: []MaskedPort{
				{0b0000000000010111, 0b1111111111111111}, // 23
				{0b0000000000011000, 0b1111111111111111}, // 24
			},
		},
		{
			start: 0,
			end:   0x7fff,
			expected: []MaskedPort{
				{port: 0x0, mask: 0x8000}, // 0-0x7fff
			},
		},
		{
			start: 256,
			end:   256,
			expected: []MaskedPort{
				{port: 0x100, mask: 0xffff},
			},
		},
		{
			start: 65535,
			end:   65535,
			expected: []MaskedPort{
				{port: 65535, mask: 0xffff},
			},
		},
		{
			start: 32767,
			end:   32768,
			expected: []MaskedPort{
				{port: 0x7fff, mask: 0xffff},
				{port: 0x8000, mask: 0xffff},
			},
		},
		{
			start: 0b0101010101010101, // 0x5555
			end:   0b0101010111010101, // 0x55d5
			expected: []MaskedPort{
				{port: 0b0101010101010101, mask: 0b1111111111111111},
				{port: 0b0101010101010110, mask: 0b1111111111111110},
				{port: 0b0101010101011000, mask: 0b1111111111111000},
				{port: 0b0101010101100000, mask: 0b1111111111100000},
				{port: 0b0101010110000000, mask: 0b1111111111000000},
				{port: 0b0101010111000000, mask: 0b1111111111110000},
				{port: 0b0101010111010000, mask: 0b1111111111111100},
				{port: 0b0101010111010100, mask: 0b1111111111111110},
			},
		},
		// This is all ports.
		{
			start: 0,
			end:   0,
			expected: []MaskedPort{
				{port: 0, mask: 0},
			},
		},
		// This is too.
		{
			start: 0,
			end:   65535,
			expected: []MaskedPort{
				{port: 0, mask: 0},
			},
		},
		// This is valid, as "0" defines no range.
		{
			start: 65535,
			end:   0,
			expected: []MaskedPort{
				{port: 0xffff, mask: 0xffff}, // 65535
			},
		},
		// These remaining tests are testing invalid cases where start >= end.
		// For now, these cases return the start port with a full mask,
		// indicating that only the start port should be part of the range.
		// This is technically correct for the case of end port being "0"
		// and the value of the port, but is ambiguous otherwise.
		{
			start: 65535,
			end:   1,
			expected: []MaskedPort{
				{port: 0xffff, mask: 0xffff}, // 65535
			},
		},
		{
			start: 65530,
			end:   5,
			expected: []MaskedPort{
				{port: 0xfffa, mask: 0xffff}, // 65530
			},
		},
		{
			start: 10,
			end:   5,
			expected: []MaskedPort{
				{port: 0xa, mask: 0xffff}, // 10
			},
		},
	}

	for i := range testCases {
		test := &testCases[i]
		maskedPorts := PortRangeToMaskedPorts(test.start, test.end)
		// Sort the returned slice so that PortRangeToMaskedPorts() can return masked ports
		// in any order that is convenient for it.
		sort.Slice(maskedPorts, func(i, j int) bool {
			return maskedPorts[i].port < maskedPorts[j].port
		})
		t.Logf("TestPortRange test case: 0x%x-0x%x (%d-%d)", test.start, test.end, test.start, test.end)
		require.Equal(t, test.expected, maskedPorts)
		// Validate when given a proper range
		if test.start <= test.end {
			// Validation checks that the masked ports form a continuous range
			validateMaskedPorts(t, maskedPorts, test.start, test.end)
		}
	}
}
