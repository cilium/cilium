// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupNodeMapSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	require.Nil(tb, err)
}

func TestNodeMap(t *testing.T) {
	setupNodeMapSuite(t)
	nodeMap := newMap("test_cilium_node_map", defaultConfig)
	err := nodeMap.init()
	require.Nil(t, err)
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
	require.Nil(t, err)
	require.Equal(t, 0, len(bpfNodeIDMap))

	err = nodeMap.Update(net.ParseIP("10.1.0.0"), 10)
	require.Nil(t, err)
	err = nodeMap.Update(net.ParseIP("10.1.0.1"), 20)
	require.Nil(t, err)

	bpfNodeIDMap = map[uint16]string{}
	err = nodeMap.IterateWithCallback(toMap)
	require.Nil(t, err)
	require.Equal(t, 2, len(bpfNodeIDMap))

	err = nodeMap.Delete(net.ParseIP("10.1.0.0"))
	require.Nil(t, err)

	bpfNodeIDMap = map[uint16]string{}
	err = nodeMap.IterateWithCallback(toMap)
	require.Nil(t, err)
	require.Equal(t, 1, len(bpfNodeIDMap))
}
