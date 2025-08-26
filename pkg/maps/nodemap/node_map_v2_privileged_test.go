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

func setupNodeMapV2TestSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestNodeMapV2(t *testing.T) {
	setupNodeMapV2TestSuite(t)
	logger := hivetest.Logger(t)
	nodeMap := newMapV2(logger, "test_cilium_node_map_v2", Config{
		NodeMapMax: 1024,
	})
	err := nodeMap.init()
	require.NoError(t, err)
	defer nodeMap.bpfMap.Unpin()

	bpfNodeIDMap := map[uint16]string{}
	bpfNodeSPI := []uint8{}
	toMap := func(key *NodeKey, val *NodeValueV2) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		bpfNodeIDMap[val.NodeID] = address
		bpfNodeSPI = append(bpfNodeSPI, uint8(val.SPI))
	}

	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Empty(t, bpfNodeIDMap)
	require.Empty(t, bpfNodeSPI)

	err = nodeMap.Update(net.ParseIP("10.1.0.0"), 10, 3)
	require.NoError(t, err)
	err = nodeMap.Update(net.ParseIP("10.1.0.1"), 20, 3)
	require.NoError(t, err)

	bpfNodeIDMap = map[uint16]string{}
	bpfNodeSPI = []uint8{}
	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Len(t, bpfNodeIDMap, 2)
	require.Len(t, bpfNodeSPI, 2)

	err = nodeMap.Delete(net.ParseIP("10.1.0.0"))
	require.NoError(t, err)

	bpfNodeIDMap = map[uint16]string{}
	bpfNodeSPI = []uint8{}
	err = nodeMap.IterateWithCallback(toMap)
	require.NoError(t, err)
	require.Len(t, bpfNodeIDMap, 1)
	require.Len(t, bpfNodeSPI, 1)
}
