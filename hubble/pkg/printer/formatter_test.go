// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package printer

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUint64Grouping(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{
			n:    0,
			want: "0",
		}, {
			n:    1,
			want: "1",
		}, {
			n:    10,
			want: "10",
		}, {
			n:    100,
			want: "100",
		}, {
			n:    1_000,
			want: "1,000",
		}, {
			n:    10_000,
			want: "10,000",
		}, {
			n:    100_000,
			want: "100,000",
		}, {
			n:    1_000_000,
			want: "1,000,000",
		}, {
			n:    math.MaxUint64,
			want: "18,446,744,073,709,551,615",
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d => %s", tt.n, tt.want), func(t *testing.T) {
			got := uint64Grouping(tt.n)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatDurationNS(t *testing.T) {
	tests := []struct {
		n    uint64
		want string
	}{
		{
			n:    0,
			want: "0s",
		}, {
			n:    1,
			want: "1ns",
		}, {
			n:    10,
			want: "10ns",
		}, {
			n:    100,
			want: "100ns",
		}, {
			n:    1000,
			want: "1µs",
		}, {
			n:    10_000,
			want: "10µs",
		}, {
			n:    100_000,
			want: "100µs",
		}, {
			n:    1_000_000,
			want: "1ms",
		}, {
			n:    10_000_000,
			want: "10ms",
		}, {
			n:    100_000_000,
			want: "100ms",
		}, {
			n:    1_000_000_000,
			want: "1s",
		}, {
			n:    10e9,
			want: "10s",
		}, {
			n:    10e10,
			want: "1m40s",
		}, {
			n:    10e11,
			want: "16m40s",
		}, {
			n:    10e12,
			want: "2h46m40s",
		}, {
			n:    10e13,
			want: "27h46m40s",
		}, {
			n:    10e14,
			want: "277h46m40s",
		}, {
			n:    10e15,
			want: "2777h46m40s",
		}, {
			n:    10e16,
			want: "27777h46m40s",
		}, {
			n:    10e17,
			want: "277777h46m40s",
		}, {
			n:    math.MaxInt64,
			want: "2562047h47m16.854775807s",
		}, {
			n:    math.MaxInt64 + 1,
			want: "9223372036854775808ns",
		}, {
			n:    math.MaxUint64,
			want: "18446744073709551615ns",
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d => %s", tt.n, tt.want), func(t *testing.T) {
			got := formatDurationNS(tt.n)
			assert.Equal(t, tt.want, got)
		})
	}
}
