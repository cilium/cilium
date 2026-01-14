// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintConstants(t *testing.T) {
	consts := []any{
		struct{ Foo int }{Foo: 42},
		map[string]any{"baz": true},
		uint32(123),
	}
	assert.Equal(t, "[]", printConstants(nil))
	assert.Equal(t, `["foo"]`, printConstants([]any{nil, "foo"}))
	assert.Equal(t, "[]", printConstants([]int{}))
	assert.Equal(t, "[]", printConstants([]any{}))
	assert.Equal(t, "[]", printConstants([]any{nil, nil}))
	assert.Equal(t, `[42]`, printConstants(42))
	assert.Equal(t, `[42, "foo"]`, printConstants([]any{42, "foo"}))

	assert.Equal(t, `[struct { Foo int }{Foo:42}, map[string]interface {}{"baz":true}, 0x7b]`, printConstants(consts))
}
