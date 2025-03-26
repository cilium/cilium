// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupNodeMapSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	logger := hivetest.Logger(tb)
	bpf.CheckOrMountFS(logger, "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestNodeMap(t *testing.T) {
	setupNodeMapSuite(t)
	logger := hivetest.Logger(t)
	nodeMap := newMap(logger, "test_cilium_node_map", defaultConfig)
	err := nodeMap.init()
	require.NoError(t, err)
	defer nodeMap.bpfMap.Unpin()

	bpfNodeIDMap := map[uint16]string{}
	toMap := func(key *NodeKey, val *NodeValue) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		bpfNodeIDMap[val.NodeID] = address
	}

	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Empty(t, bpfNodeIDMap)

	err = nodeMap.Update(net.ParseIP("10.1.0.0"), 10)
	require.NoError(t, err)
	err = nodeMap.Update(net.ParseIP("10.1.0.1"), 20)
	require.NoError(t, err)

	bpfNodeIDMap = map[uint16]string{}
	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Len(t, bpfNodeIDMap, 2)

	err = nodeMap.Delete(net.ParseIP("10.1.0.0"))
	require.NoError(t, err)

	bpfNodeIDMap = map[uint16]string{}
	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Len(t, bpfNodeIDMap, 1)
}
