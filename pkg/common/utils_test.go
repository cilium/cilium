// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestC2GoArray(t *testing.T) {
	require.Equal(t, []byte{0, 0x01, 0x02, 0x03}, C2GoArray("0x0, 0x1, 0x2, 0x3"))
	require.Equal(t, []byte{0, 0xFF, 0xFF, 0xFF}, C2GoArray("0x0, 0xff, 0xff, 0xff"))
	require.Equal(t, []byte{0xa, 0xbc, 0xde, 0xf1}, C2GoArray("0xa, 0xbc, 0xde, 0xf1"))
	require.Equal(t, []byte{0}, C2GoArray("0x0"))
	require.Equal(t, []byte{}, C2GoArray(""))
}

func TestGoArray2C(t *testing.T) {
	tests := []struct {
		input  []byte
		output string
	}{
		{
			input:  []byte{0, 0x01, 0x02, 0x03},
			output: "0x0, 0x1, 0x2, 0x3",
		},
		{
			input:  []byte{0, 0xFF, 0xFF, 0xFF},
			output: "0x0, 0xff, 0xff, 0xff",
		},
		{
			input:  []byte{0xa, 0xbc, 0xde, 0xf1},
			output: "0xa, 0xbc, 0xde, 0xf1",
		},
		{
			input:  []byte{0},
			output: "0x0",
		},
		{
			input:  []byte{},
			output: "",
		},
	}

	for _, test := range tests {
		require.Equal(t, test.output, GoArray2C(test.input))
	}
}
