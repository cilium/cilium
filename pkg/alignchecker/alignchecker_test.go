// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlignChecker(t *testing.T) {
	type foo struct {
		_ [4]uint32 `align:"$union0"`
		_ uint32    `align:"$union1"`
		_ uint8     `align:"family"`
		_ uint8     `align:"pad4"`
		_ uint16    `align:"pad5"`
	}

	type foo2 struct {
		_ foo
	}

	type foo3 struct {
		_ [4]uint32 `align:"$union0.ip6"`
		_ uint32    `align:"$union1.p2"`
		_ uint8     `align:"family"`
		_ uint8     `align:"pad4"`
		_ uint16    `align:"pad5"`
	}

	type foo4 struct {
		_ uint32 `align:"$union0.$struct0.ip4"`
		_ uint32 `align:"$union0.$struct0.pad1"`
		_ uint32 `align:"$union0.$struct0.pad2"`
		_ uint32 `align:"$union0.$struct0.pad3"`
		_ uint32 `align:"$union1.p1"`
		_ uint8  `align:"family"`
		_ uint8  `align:"pad4"`
		_ uint16 `align:"pad5"`
	}

	type invalidSize struct {
		_ uint32
	}

	type invalidOffset struct {
		_ [4]uint32 `align:"$union0"`
		_ uint32    `align:"$union1"`
		_ uint16    `align:"family"`
		_ uint8     `align:"pad4"`
		_ uint8     `align:"pad5"`
	}

	// Struct alignment value is 16 bits, so this will carry 8 bits of trailing
	// padding.
	type trailingPadding struct {
		_ uint16
		_ uint8
		// _ uint8 implicit padding
	}

	type toCheck map[string][]any

	testCases := []struct {
		cName   string
		goTypes []any
		err     string
	}{
		{
			"foo",
			[]any{foo{}},
			"",
		},
		{
			"foo",
			[]any{foo2{}},
			"",
		},
		{
			"foo",
			[]any{foo{}, foo2{}},
			"",
		},
		{
			"foo",
			[]any{foo3{}},
			"",
		},
		{
			"foo",
			[]any{foo4{}},
			"",
		},
		{
			"foo",
			[]any{invalidSize{}},
			"invalidSize(4) size does not match foo(24)",
		},
		{
			"foo",
			[]any{invalidOffset{}},
			"offset(22) does not match foo.pad4(21)",
		},
		{
			"bar",
			[]any{foo{}},
			"not found",
		},
		{
			"foo",
			[]any{trailingPadding{}},
			"implicit trailing padding",
		},
	}

	for _, tt := range testCases {
		err := CheckStructAlignments("testdata/bpf_foo.o", toCheck{tt.cName: tt.goTypes}, true)
		if tt.err != "" {
			assert.NotNil(t, err)
			assert.Contains(t, err.Error(), tt.err)
			continue
		}

		assert.Nil(t, err)
	}
}
