// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package typeurl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIndexRoundTrip(t *testing.T) {
	seen := NewSet()
	for index := range Indices() {
		url := index.URL()
		require.NotEmpty(t, url)
		roundTrip, ok := FromURL(url)
		require.True(t, ok)
		require.Equal(t, index, roundTrip)
		seen.Insert(index)
	}
	require.Equal(t, int(Count), seen.Len())

	index, ok := FromURL("type.googleapis.com/example.Unknown")
	require.False(t, ok)
	require.Equal(t, Count, index)
	require.Empty(t, Count.URL())
}

func TestFixedMapTracksZeroValuesAndInitialization(t *testing.T) {
	var values Map[int]
	require.False(t, values.Known())
	require.True(t, values.Empty())

	values = NewMap[int]()
	require.True(t, values.Known())
	require.True(t, values.Empty())

	values.Set(Listener, 0)
	value, ok := values.Get(Listener)
	require.True(t, ok)
	require.Zero(t, value)
	require.Equal(t, 1, values.Len())

	values.Remove(Listener)
	require.True(t, values.Known())
	require.True(t, values.Empty())
}
