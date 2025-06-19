// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package nat

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupExclusionMapsTest(tb testing.TB) {
	testutils.PrivilegedTest(tb)
	logger := hivetest.Logger(tb)

	bpf.CheckOrMountFS(logger, "")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")
}

func TestPrivilegedInitNatExclusionMaps_OpensMaps(t *testing.T) {
	setupExclusionMapsTest(t)

	logger := hivetest.Logger(t)

	require.NoError(t, InitNatExclusionMaps(logger))

	require.NotNil(t, NatExclusionMapIPv4, "IPv4 exclusion map should be initialized")
	require.NotNil(t, NatExclusionMapIPv6, "IPv6 exclusion map should be initialized")
}

func TestPrivilegedNatExclusionMaps_InsertDeleteCIDR(t *testing.T) {
	setupExclusionMapsTest(t)

	logger := hivetest.Logger(t)
	require.NoError(t, InitNatExclusionMaps(logger))

	// Prepare test CIDRs
	_, v4net, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	_, v6net, err := net.ParseCIDR("2001:db8::/32")
	require.NoError(t, err)

	// Insert CIDR and verify existence
	require.NoError(t, NatExclusionMapIPv4.InsertCIDR(*v4net))
	require.True(t, NatExclusionMapIPv4.CIDRExists(*v4net))
	require.NoError(t, NatExclusionMapIPv6.InsertCIDR(*v6net))
	require.True(t, NatExclusionMapIPv6.CIDRExists(*v6net))

	// Delete both and verify removal
	require.NoError(t, NatExclusionMapIPv4.DeleteCIDR(*v4net))
	require.False(t, NatExclusionMapIPv4.CIDRExists(*v4net))
	require.NoError(t, NatExclusionMapIPv6.DeleteCIDR(*v6net))
	require.False(t, NatExclusionMapIPv6.CIDRExists(*v6net))
}
