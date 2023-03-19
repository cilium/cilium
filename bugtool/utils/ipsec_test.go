// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHashEncryptionKeys tests proper hashing of keys. Lines in which `auth` or
// other relevant pattern are found but not the hexadecimal keys are intentionally
// redacted from the output to avoid accidental leaking of keys.
func TestHashEncryptionKeys(t *testing.T) {
	testdata := []struct {
		input  string
		output string
	}{
		{
			// `auth` and hexa string
			input:  "<garbage> auth foo bar 0x123456af baz",
			output: "<garbage> auth foo bar [hash:21d466b493f5c133edc008ee375e849fe5babb55d31550c25b993d151038c8a8] baz",
		},
		{
			// `auth` but no hexa string
			input:  "<garbage> auth foo bar ###23456af baz",
			output: "[redacted]",
		},
		{
			// `enc` and hexa string
			input:  "<garbage> enc foo bar 0x123456af baz",
			output: "<garbage> enc foo bar [hash:21d466b493f5c133edc008ee375e849fe5babb55d31550c25b993d151038c8a8] baz",
		},
		{
			// nothing
			input:  "<garbage> xxxx foo bar 0x123456af baz",
			output: "<garbage> xxxx foo bar 0x123456af baz",
		},
	}

	for _, v := range testdata {
		modifiedString := HashEncryptionKeys([]byte(v.input))
		assert.Equal(t, v.output, string(modifiedString))
	}
}
