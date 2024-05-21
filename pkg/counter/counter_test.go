// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCounter(t *testing.T) {
	sc := make(Counter[string])
	require.True(t, sc.Add("foo"))
	require.Equal(t, 1, len(sc))
	require.False(t, sc.Add("foo"))
	require.Equal(t, 1, len(sc))
	require.True(t, sc.Add("bar"))
	require.Equal(t, 2, len(sc))
	nsc := sc.DeepCopy()
	require.Equal(t, nsc, sc)
	require.False(t, sc.Delete("foo"))
	require.Equal(t, 2, len(sc))
	require.True(t, sc.Delete("bar"))
	require.Equal(t, 1, len(sc))
	require.True(t, sc.Delete("foo"))
	require.Equal(t, 0, len(sc))
	require.True(t, sc.Add("foo"))
	require.Equal(t, 1, len(sc))

	ic := make(Counter[int])
	require.True(t, ic.Add(42))
	require.Equal(t, 1, len(ic))
	require.False(t, ic.Add(42))
	require.Equal(t, 1, len(ic))
	require.True(t, ic.Add(100))
	require.Equal(t, 2, len(ic))
	nic := ic.DeepCopy()
	require.Equal(t, nic, ic)
	require.False(t, ic.Delete(42))
	require.Equal(t, 2, len(ic))
	require.True(t, ic.Delete(100))
	require.Equal(t, 1, len(ic))
	require.True(t, ic.Delete(42))
	require.Equal(t, 0, len(ic))
	require.True(t, ic.Add(100))
	require.Equal(t, 1, len(ic))

	ac := make(Counter[netip.Addr])
	require.True(t, ac.Add(netip.MustParseAddr("10.0.0.1")))
	require.Equal(t, 1, len(ac))
	require.False(t, ac.Add(netip.MustParseAddr("10.0.0.1")))
	require.Equal(t, 1, len(ac))
	require.True(t, ac.Add(netip.MustParseAddr("::1")))
	require.Equal(t, 2, len(ac))
	require.True(t, ac.Add(netip.MustParseAddr("192.168.0.1")))
	require.Equal(t, 3, len(ac))
	require.True(t, ac.Add(netip.MustParseAddr("::ffff:10.0.0.1")))
	require.Equal(t, 4, len(ac))
	nac := ac.DeepCopy()
	require.Equal(t, nac, ac)
	require.False(t, ac.Delete(netip.MustParseAddr("10.0.0.1")))
	require.Equal(t, 4, len(ac))
	require.True(t, ac.Delete(netip.MustParseAddr("10.0.0.1")))
	require.Equal(t, 3, len(ac))
}
