// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/statedb/index"
)

func TestKeySet_Single(t *testing.T) {
	ks := index.NewKeySet([]byte("baz"))
	require.EqualValues(t, "baz", ks.First())
	require.True(t, ks.Exists([]byte("baz")))
	require.False(t, ks.Exists([]byte("foo")))
	vs := []index.Key{}
	ks.Foreach(func(bs index.Key) {
		vs = append(vs, bs)
	})
	require.ElementsMatch(t, vs, []index.Key{index.Key("baz")})
}

func TestKeySet_Multi(t *testing.T) {
	ks := index.NewKeySet([]byte("baz"), []byte("quux"))
	require.EqualValues(t, "baz", ks.First())
	require.True(t, ks.Exists([]byte("baz")))
	require.True(t, ks.Exists([]byte("quux")))
	require.False(t, ks.Exists([]byte("foo")))
	vs := [][]byte{}
	ks.Foreach(func(bs index.Key) {
		vs = append(vs, bs)
	})
	require.ElementsMatch(t, vs, [][]byte{[]byte("baz"), []byte("quux")})
}
