// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package murmur3

import (
	"testing"
)

func TestMurmur3(t *testing.T) {
	var tests = []struct {
		seed uint32
		h1   uint64
		h2   uint64
		s    string
	}{
		{0, 0x0000000000000000, 0x0000000000000000, ""},
		{1234, 0x1629cce705a7069c, 0x316c1fbd953aaecd, "hello world"},
		{500, 0x188f69f0abbd67de, 0x1b0eeb31b4c00cb6, "lorem ipsum dolor sit amet"},
		{31, 0x24b05ffca412286a, 0x7d81ac914b62fe96, "this is a test of 31 bytes long"},
		{0xd09, 0x5e0fd714b3169ae6, 0x2f36e811c1535dc7, "The quick brown fox jumps over the lazy dog."},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			h1, h2 := Hash128([]byte(tt.s), tt.seed)
			if want, got := tt.h1, h1; want != got {
				t.Errorf("Unexpected h1:\n\twant:\t0x%x,\n\tgot:\t0x%x", want, got)
			}
			if want, got := tt.h2, h2; want != got {
				t.Errorf("Unexpected h2:\n\twant:\t0x%x,\n\tgot:\t0x%x", want, got)
			}
		})
	}
}
