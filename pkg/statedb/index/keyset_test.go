// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/statedb/index"
)

func TestKeySet_FromEmpty(t *testing.T) {
	ks := index.NewKeySet()
	require.Nil(t, ks.First())
	ks.Foreach(func(_ []byte) {
		t.Fatalf("Foreach on NewKeySet called function")
	})
	require.False(t, ks.Exists(nil))
	require.False(t, ks.Exists([]byte{1, 2, 3}))

	ks.Append([]byte("foo"))
	require.EqualValues(t, "foo", ks.First())
	ks.Foreach(func(bs []byte) {
		require.EqualValues(t, "foo", bs)
	})
	require.True(t, ks.Exists([]byte("foo")))

	ks.Append([]byte("bar"))
	require.EqualValues(t, "foo", ks.First())
	vs := [][]byte{}
	ks.Foreach(func(bs []byte) {
		vs = append(vs, bs)
	})
	require.ElementsMatch(t, vs, [][]byte{[]byte("foo"), []byte("bar")})
	require.True(t, ks.Exists([]byte("foo")))
	require.True(t, ks.Exists([]byte("bar")))
	require.False(t, ks.Exists([]byte("baz")))
}

func TestKeySet_FromNonEmpty(t *testing.T) {
	ks := index.NewKeySet([]byte("baz"), []byte("quux"))
	require.EqualValues(t, "baz", ks.First())
	require.True(t, ks.Exists([]byte("baz")))
	require.True(t, ks.Exists([]byte("quux")))
	require.False(t, ks.Exists([]byte("foo")))
	vs := [][]byte{}
	ks.Foreach(func(bs []byte) {
		vs = append(vs, bs)
	})
	require.ElementsMatch(t, vs, [][]byte{[]byte("baz"), []byte("quux")})
}
