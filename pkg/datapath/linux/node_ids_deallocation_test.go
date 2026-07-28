// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	nodemapfake "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestDeallocateIDsForNode(t *testing.T) {
	t.Run("no allocated ID", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler := newNodeIDTestHandler(t, nodeMap)
		node := nodeIDTestNode("node", "10.0.0.1")

		require.NoError(t, deallocateNodeIDForTest(handler, &node))
		require.False(t, handler.nodeIDs.Remove(idpool.NoID))
	})

	t.Run("single node ID", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler := newNodeIDTestHandler(t, nodeMap)
		node := nodeIDTestNode("node", "10.0.0.1", "10.0.0.2")
		nodeID := allocateNodeIDForTest(t, handler, &node)

		require.NoError(t, deallocateNodeIDForTest(handler, &node))
		requireNodeIDRemoved(t, handler, nodeMap, nodeID, "10.0.0.1", "10.0.0.2")
	})

	t.Run("multiple node IDs", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler, logs := newBufferedNodeIDTestHandler(t, nodeMap)
		nodeIP1 := nodeIDTestNode("node-1", "10.0.0.1")
		nodeIP2 := nodeIDTestNode("node-2", "10.0.0.2")
		nodeID1 := allocateNodeIDForTest(t, handler, &nodeIP1)
		nodeID2 := allocateNodeIDForTest(t, handler, &nodeIP2)
		require.NotEqual(t, nodeID1, nodeID2)

		node := nodeIDTestNode("node", "10.0.0.1", "10.0.0.2")
		require.NoError(t, deallocateNodeIDForTest(handler, &node))
		require.Contains(t, logs.String(), "Found two node IDs for the same node")
		requireNodeIDRemoved(t, handler, nodeMap, nodeID1, "10.0.0.1")
		requireNodeIDRemoved(t, handler, nodeMap, nodeID2, "10.0.0.2")
	})

	t.Run("mapped and unmapped IPs", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler, logs := newBufferedNodeIDTestHandler(t, nodeMap)
		mappedNode := nodeIDTestNode("node", "10.0.0.2")
		nodeID := allocateNodeIDForTest(t, handler, &mappedNode)

		node := nodeIDTestNode("node", "10.0.0.1", "10.0.0.2")
		require.NoError(t, deallocateNodeIDForTest(handler, &node))
		require.NotContains(t, logs.String(), "Found two node IDs for the same node")
		requireNodeIDRemoved(t, handler, nodeMap, nodeID, "10.0.0.2")
	})

	t.Run("stale foreign IP", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler := newNodeIDTestHandler(t, nodeMap)
		node := nodeIDTestNode("node", "10.0.0.1")
		nodeID := allocateNodeIDForTest(t, handler, &node)
		mapNodeIDForTest(t, handler, "10.0.0.2", nodeID)

		require.NoError(t, deallocateNodeIDForTest(handler, &node))
		requireNodeIDRemoved(t, handler, nodeMap, nodeID, "10.0.0.1", "10.0.0.2")
	})

	t.Run("IP reused by live node", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler := newNodeIDTestHandler(t, nodeMap)
		staleNode := nodeIDTestNode("stale-node", "10.0.0.1")
		liveNode := nodeIDTestNode("live-node", "10.0.0.2")
		staleNodeID := allocateNodeIDForTest(t, handler, &staleNode)
		liveNodeID := allocateNodeIDForTest(t, handler, &liveNode)
		addLiveNodeForTest(handler, &liveNode)

		deletedNode := nodeIDTestNode("stale-node", "10.0.0.1", "10.0.0.2")
		require.NoError(t, deallocateNodeIDForTest(handler, &deletedNode))
		requireNodeIDRemoved(t, handler, nodeMap, staleNodeID, "10.0.0.1")
		requireNodeIDPresent(t, handler, nodeMap, liveNodeID, "10.0.0.2")
	})

	t.Run("node ID shared with live node", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		handler := newNodeIDTestHandler(t, nodeMap)
		staleNode := nodeIDTestNode("stale-node", "10.0.0.1")
		liveNode := nodeIDTestNode("live-node", "10.0.0.2")
		nodeID := allocateNodeIDForTest(t, handler, &staleNode)
		mapNodeIDForTest(t, handler, "10.0.0.2", nodeID)
		addLiveNodeForTest(handler, &liveNode)

		require.NoError(t, deallocateNodeIDForTest(handler, &staleNode))
		requireNodeIDMappingMissing(t, handler, nodeMap, "10.0.0.1")
		requireNodeIDPresent(t, handler, nodeMap, nodeID, "10.0.0.2")
	})

	t.Run("BPF map delete failure", func(t *testing.T) {
		nodeMap := nodemapfake.NewFakeNodeMapV2()
		ip := netip.MustParseAddr("10.0.0.1")
		handler := newNodeIDTestHandler(t, &deleteFailingNodeMap{
			MapV2:  nodeMap,
			failIP: ip,
		})
		node := nodeIDTestNode("node", ip.String())
		nodeID := allocateNodeIDForTest(t, handler, &node)

		err := deallocateNodeIDForTest(handler, &node)
		require.ErrorContains(t, err, "failed to unmap node IP")
		requireNodeIDPresent(t, handler, nodeMap, nodeID, ip.String())
	})
}

type deleteFailingNodeMap struct {
	nodemap.MapV2
	failIP netip.Addr
}

type nodeMapLookup interface {
	Lookup(netip.Addr) (*nodemap.NodeValueV2, error)
}

func (m *deleteFailingNodeMap) Delete(ip netip.Addr) error {
	if ip == m.failIP {
		return errors.New("test node map delete failure")
	}
	return m.MapV2.Delete(ip)
}

func newNodeIDTestHandler(t *testing.T, nodeMap nodemap.MapV2) *linuxNodeHandler {
	t.Helper()
	return newNodeIDTestHandlerWithLogger(t, hivetest.Logger(t), nodeMap)
}

func newBufferedNodeIDTestHandler(t *testing.T, nodeMap nodemap.MapV2) (*linuxNodeHandler, *bytes.Buffer) {
	t.Helper()
	logs := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(logs, nil))
	return newNodeIDTestHandlerWithLogger(t, logger, nodeMap), logs
}

func newNodeIDTestHandlerWithLogger(
	t *testing.T,
	logger *slog.Logger,
	nodeMap nodemap.MapV2,
) *linuxNodeHandler {
	t.Helper()
	return newNodeHandler(
		logger,
		DatapathConfiguration{},
		nodeMap,
		kpr.KPRConfig{},
		&fakeipsec.Agent{},
		fakeipsec.Config{},
		node.NewTestLocalNodeStore(node.LocalNode{}),
	)
}

func nodeIDTestNode(name string, ips ...string) nodeTypes.Node {
	addresses := make([]nodeTypes.Address, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   netip.MustParseAddr(ip).AsSlice(),
		})
	}
	return nodeTypes.Node{
		Name:        name,
		IPAddresses: addresses,
	}
}

func allocateNodeIDForTest(t *testing.T, handler *linuxNodeHandler, node *nodeTypes.Node) uint16 {
	t.Helper()
	handler.mutex.Lock()
	defer handler.mutex.Unlock()

	nodeID, err := handler.allocateIDForNode(nil, node)
	require.NoError(t, err)
	require.NotZero(t, nodeID)
	return nodeID
}

func mapNodeIDForTest(t *testing.T, handler *linuxNodeHandler, ip string, nodeID uint16) {
	t.Helper()
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	require.NoError(t, handler.mapNodeID(ip, nodeID, 0))
}

func deallocateNodeIDForTest(handler *linuxNodeHandler, node *nodeTypes.Node) error {
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	return handler.deallocateIDForNode(node)
}

func addLiveNodeForTest(handler *linuxNodeHandler, node *nodeTypes.Node) {
	handler.mutex.Lock()
	defer handler.mutex.Unlock()
	handler.nodes[node.Identity()] = node
}

func requireNodeIDRemoved(
	t *testing.T,
	handler *linuxNodeHandler,
	nodeMap nodeMapLookup,
	nodeID uint16,
	ips ...string,
) {
	t.Helper()
	for _, ip := range ips {
		requireNodeIDMappingMissing(t, handler, nodeMap, ip)
	}
	require.NotContains(t, handler.nodeIPsByIDs, nodeID)
	require.True(t, handler.nodeIDs.Remove(idpool.ID(nodeID)))
}

func requireNodeIDMappingMissing(
	t *testing.T,
	handler *linuxNodeHandler,
	nodeMap nodeMapLookup,
	ip string,
) {
	t.Helper()
	require.NotContains(t, handler.nodeIDsByIPs, ip)
	_, err := nodeMap.Lookup(netip.MustParseAddr(ip))
	require.Error(t, err)
}

func requireNodeIDPresent(
	t *testing.T,
	handler *linuxNodeHandler,
	nodeMap nodeMapLookup,
	nodeID uint16,
	ip string,
) {
	t.Helper()
	require.Equal(t, nodeID, handler.nodeIDsByIPs[ip])
	require.Contains(t, handler.nodeIPsByIDs[nodeID], ip)
	value, err := nodeMap.Lookup(netip.MustParseAddr(ip))
	require.NoError(t, err)
	require.Equal(t, nodeID, value.NodeID)
	require.False(t, handler.nodeIDs.Remove(idpool.ID(nodeID)))
}
