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

func setupSourceExclusionMapsTest(tb testing.TB) {
	testutils.PrivilegedTest(tb)
	logger := hivetest.Logger(tb)

	bpf.CheckOrMountFS(logger, "")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")
}

func TestPrivilegedEnsureDefaultSourceExclusionMaps_OpensMaps(t *testing.T) {
	setupSourceExclusionMapsTest(t)

	logger := hivetest.Logger(t)
	em, err := EnsureDefaultSourceExclusionMaps(logger)
	require.NoError(t, err)
	require.NotNil(t, em, "SourceExclusionMaps should be initialized")
	require.NotNil(t, em.IPv4, "IPv4 exclusion map should be initialized")
	require.NotNil(t, em.IPv6, "IPv6 exclusion map should be initialized")
}

func TestPrivilegedSourceExclusionMaps_InsertDeleteCIDR(t *testing.T) {
	setupSourceExclusionMapsTest(t)

	logger := hivetest.Logger(t)
	em, err := NewSourceExclusionMaps(logger, "nat_exclusion_test_1_v4", "nat_exclusion_test_1_v6", 16)
	require.NoError(t, err)
	em2, err := NewSourceExclusionMaps(logger, "nat_exclusion_test_2_v4", "nat_exclusion_test_2_v6", 16)
	require.NoError(t, err)
	require.NotNil(t, em)
	require.NotNil(t, em2)

	// Prepare test CIDRs
	_, v4net, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	_, v6net, err := net.ParseCIDR("2001:db8::/32")
	require.NoError(t, err)

	// Insert CIDR and verify existence
	require.NoError(t, em.IPv4.InsertCIDR(*v4net))
	require.True(t, em.IPv4.CIDRExists(*v4net))
	require.NoError(t, em.IPv6.InsertCIDR(*v6net))
	require.True(t, em.IPv6.CIDRExists(*v6net))

	require.NoError(t, em2.IPv4.InsertCIDR(*v4net))
	require.True(t, em2.IPv4.CIDRExists(*v4net))
	require.NoError(t, em2.IPv6.InsertCIDR(*v6net))
	require.True(t, em2.IPv6.CIDRExists(*v6net))

	// Delete both and verify removal
	require.NoError(t, em.IPv4.DeleteCIDR(*v4net))
	require.False(t, em.IPv4.CIDRExists(*v4net))
	require.NoError(t, em.IPv6.DeleteCIDR(*v6net))
	require.False(t, em.IPv6.CIDRExists(*v6net))

	require.NoError(t, em2.IPv4.DeleteCIDR(*v4net))
	require.False(t, em2.IPv4.CIDRExists(*v4net))
	require.NoError(t, em2.IPv6.DeleteCIDR(*v6net))
	require.False(t, em2.IPv6.CIDRExists(*v6net))
}
