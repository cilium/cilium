// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructToMap(t *testing.T) {
	type e struct {
		B int `config:"b"`
	}
	type s struct {
		A int `config:"a"`
		e

		ignored bool
	}
	obj := s{1, e{2}, true}
	want := map[string]any{"a": 1, "b": 2}

	values, err := Map(obj)
	require.NoError(t, err)
	assert.Equal(t, want, values)

	values, err = Map(&obj)
	require.NoError(t, err)
	assert.Equal(t, want, values)

	values, err = Map([]any{&obj})
	require.NoError(t, err)
	assert.Equal(t, want, values)

	type compl struct {
		C int `config:"c"`
	}
	values, err = Map([]any{&obj, &compl{3}})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": 1, "b": 2, "c": 3}, values)

	type dup struct {
		Foo int `config:"a"`
	}
	_, err = Map([]any{&obj, &dup{3}})
	require.ErrorIs(t, err, errDuplicateVariable)

	// Make sure nil interface doesn't panic.
	_, err = Map(nil)
	require.Error(t, err)

	// Make sure nil pointer doesn't panic.
	_, err = Map((*s)(nil))
	require.Error(t, err)
}
