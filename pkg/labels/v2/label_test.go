// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLabel(t *testing.T) {
	k, v, s := "my-key", "my-value", "my-source"
	l := MakeLabel(k, v, s)
	assert.Equal(t, k, l.Key())
	assert.Equal(t, v, l.Value())
	assert.Equal(t, s, l.Source())
	assert.Equal(t,
		"my-source:my-key=my-value",
		l.String())
}

func TestLabelJSON(t *testing.T) {
	k, v, s := "my-key", "my-value", "my-source"
	l := MakeLabel(k, v, s)
	assert.Equal(t, k, l.Key())
	assert.Equal(t, v, l.Value())
	assert.Equal(t, s, l.Source())

	b, err := l.MarshalJSON()
	require.NoError(t, err, "MarshalJSON")
	require.Equal(t,
		`{"key":"my-key","value":"my-value","source":"my-source"}`,
		string(b))

	var l2 Label
	err = l2.UnmarshalJSON(b)
	require.NoError(t, err, "UnmarshalJSON")
	assert.Equal(t, k, l.Key())
	assert.Equal(t, v, l.Value())
	assert.Equal(t, s, l.Source())
	assert.True(t, l.Equal(l2), "Equal")
}

func BenchmarkNewLabel(b *testing.B) {
	k, v, s := "my-bench-key", "my-bench-value", "my-bench-source"
	for range b.N {
		MakeLabel(k, v, s)
	}
}

func BenchmarkNewLabelFresh(b *testing.B) {
	for i := range b.N {
		x := strconv.FormatInt(int64(i), 10)
		MakeLabel(x, x, x)
	}
}
