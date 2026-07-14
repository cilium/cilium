// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kpr"
	nodemapfake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestNodeMapGarbageCollect(t *testing.T) {
	nodeMap := nodemapfake.NewFakeNodeMapV2()
	lnh := newNodeHandler(hivetest.Logger(t), DatapathConfiguration{}, nodeMap, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, node.NewTestLocalNodeStore(node.LocalNode{}))

	validIP := "10.0.0.1"
	staleIP := "10.0.0.2"
	nodeWithStaleIP := nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(validIP),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP(staleIP),
			},
		},
	}

	lnh.mutex.Lock()
	nodeID, err := lnh.allocateIDForNode(nil, &nodeWithStaleIP)
	lnh.mutex.Unlock()
	require.NoError(t, err)
	require.NotZero(t, nodeID)

	lnh.nodes[nodeWithStaleIP.Identity()] = &nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(validIP),
			},
		},
	}
	lnh.NodeMapGarbageCollect()

	_, err = nodeMap.Lookup(netip.MustParseAddr(validIP))
	require.NoError(t, err)
	_, err = nodeMap.Lookup(netip.MustParseAddr(staleIP))
	require.Error(t, err)
	require.Equal(t, nodeID, lnh.nodeIDsByIPs[validIP])
	require.NotContains(t, lnh.nodeIDsByIPs, staleIP)
	require.Contains(t, lnh.nodeIPsByIDs[nodeID], validIP)
	require.NotContains(t, lnh.nodeIPsByIDs[nodeID], staleIP)
	require.False(t, lnh.nodeIDs.Remove(idpool.ID(nodeID)))

	delete(lnh.nodes, nodeWithStaleIP.Identity())
	lnh.NodeMapGarbageCollect()

	_, err = nodeMap.Lookup(netip.MustParseAddr(validIP))
	require.Error(t, err)
	require.NotContains(t, lnh.nodeIDsByIPs, validIP)
	require.NotContains(t, lnh.nodeIPsByIDs, nodeID)
	require.True(t, lnh.nodeIDs.Remove(idpool.ID(nodeID)))
}
