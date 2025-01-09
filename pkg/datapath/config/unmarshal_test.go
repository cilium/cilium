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

	values, err := StructToMap(&obj)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"a": 1, "b": 2}, values)
}
