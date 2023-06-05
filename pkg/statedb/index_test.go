// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/statedb"
)

type prefixFieldTest struct {
	Prefix netip.Prefix
}

func TestNetIPPrefixFieldIndex(t *testing.T) {
	testPrefix, err := netip.ParsePrefix("1.2.3.0/24")
	require.NoError(t, err)
	checkBytes := func(bs []byte) {
		var out netip.Prefix
		out.UnmarshalBinary(bs)
		require.Equal(t, testPrefix, out)
	}

	idx := statedb.NetIPPrefixFieldIndex{Field: "Prefix"}

	ok, bs, err := idx.FromObject(prefixFieldTest{testPrefix})
	require.NoError(t, err)
	require.True(t, ok, "FromObject succeeds")
	checkBytes(bs)

	bs, err = idx.FromArgs("foo")
	require.Error(t, err, "Expected FromArgs to fail with bad type")
	require.Nil(t, bs)

	bs, err = idx.FromArgs(testPrefix)
	require.NoError(t, err, "Expected FromArgs to succeed with 'netip.Prefix'")
	checkBytes(bs)

	bs, err = idx.FromArgs(&testPrefix)
	require.NoError(t, err, "Expected FromArgs to succeed with '*netip.Prefix'")
	checkBytes(bs)
}

type ipnetFieldTest struct {
	IPNet net.IPNet
}

func TestIPNetFieldIndex(t *testing.T) {
	_, testIPNet, err := net.ParseCIDR("1.2.3.0/24")
	require.NoError(t, err)

	idx := statedb.IPNetFieldIndex{Field: "IPNet"}

	ok, bs, err := idx.FromObject(ipnetFieldTest{*testIPNet})
	require.NoError(t, err)
	require.True(t, ok, "FromObject succeeds")
	require.NotEmpty(t, bs)

	bs, err = idx.FromArgs("foo")
	require.Error(t, err, "Expected FromArgs to fail with bad type")
	require.Nil(t, bs)

	bs, err = idx.FromArgs(*testIPNet)
	require.NoError(t, err, "Expected FromArgs to succeed with 'net.IPNet'")
	require.NotEmpty(t, bs)

	bs, err = idx.FromArgs(testIPNet)
	require.NoError(t, err, "Expected FromArgs to succeed with '*net.IPNet'")
	require.NotEmpty(t, bs)
}

type ipFieldTest struct {
	IP net.IP
}

func TestIPFieldIndex(t *testing.T) {
	testIP := net.ParseIP("1.2.3.4")
	require.NotNil(t, testIP)

	idx := statedb.IPFieldIndex{Field: "IP"}

	ok, bs, err := idx.FromObject(ipFieldTest{testIP})
	require.NoError(t, err)
	require.True(t, ok, "FromObject succeeds")
	require.NotEmpty(t, bs)

	bs, err = idx.FromArgs(1234)
	require.Error(t, err, "Expected FromArgs to fail with bad type")
	require.Nil(t, bs)

	bs, err = idx.FromArgs("not-proper-ip")
	require.Error(t, err, "Expected FromArgs to fail with bad IP string")
	require.Nil(t, bs)

	bs, err = idx.FromArgs(testIP.String())
	require.NoError(t, err, "Expected FromArgs to succeed with 'string'")
	require.NotEmpty(t, bs)

	bs, err = idx.FromArgs(testIP)
	require.NoError(t, err, "Expected FromArgs to succeed with 'net.IP'")
	require.NotEmpty(t, bs)
}
