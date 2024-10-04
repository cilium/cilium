// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupTunnelMapTestSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestClusterAwareAddressing(t *testing.T) {
	setupTunnelMapTestSuite(t)
	m := NewTunnelMap("test_cilium_tunnel_map")

	err := m.OpenOrCreate()
	require.NoError(t, err)

	prefix0 := cmtypes.MustParseAddrCluster("10.0.0.1")
	prefix1 := cmtypes.MustParseAddrCluster("10.0.0.1@1")
	endpoint0 := net.ParseIP("192.168.0.1")
	endpoint1 := net.ParseIP("192.168.1.1")

	// Test insertion with bare IP
	err = m.SetTunnelEndpoint(0, prefix0, endpoint0)
	require.NoError(t, err)

	// Test insertion with AddrCluster
	err = m.SetTunnelEndpoint(0, prefix1, endpoint1)
	require.NoError(t, err)

	// Test if tunnel map can distinguish prefix0 and prefix1
	ip0, err := m.GetTunnelEndpoint(prefix0)
	require.NoError(t, err)
	require.True(t, ip0.Equal(endpoint0))

	ip1, err := m.GetTunnelEndpoint(prefix1)
	require.NoError(t, err)
	require.True(t, ip1.Equal(endpoint1))

	// Delete prefix0 and check it deletes prefix0 correctly
	err = m.DeleteTunnelEndpoint(prefix0)
	require.NoError(t, err)

	_, err = m.GetTunnelEndpoint(prefix0)
	require.Error(t, err)

	_, err = m.GetTunnelEndpoint(prefix1)
	require.NoError(t, err)

	// Delete prefix0 and check it deletes prefix0 correctly
	err = m.DeleteTunnelEndpoint(prefix1)
	require.NoError(t, err)

	_, err = m.GetTunnelEndpoint(prefix1)
	require.Error(t, err)

	err = m.Unpin()
	require.NoError(t, err)
}
