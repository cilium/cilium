// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type formatTestCase struct {
	input  []byte
	output string
}

func TestDefineIPv6(t *testing.T) {
	tests := []formatTestCase{
		{
			input:  nil,
			output: "/* BUG: bad ip define foo  */\n",
		},
		{
			input:  []byte{},
			output: "/* BUG: bad ip define foo  */\n",
		},
		{
			input:  []byte{1, 2, 3},
			output: "/* BUG: bad ip define foo 0x1, 0x2, 0x3 */\n",
		},
		{
			input: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			output: "DEFINE_IPV6(foo, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10);\n" +
				"#define foo_V\n",
		},
	}

	for _, test := range tests {
		require.Equal(t, test.output, defineIPv6("foo", test.input))
	}
}
