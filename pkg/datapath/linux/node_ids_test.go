// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/idpool"
	fakenodemap "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func newTestNodeIDHandler(t *testing.T, minID, maxID idpool.ID) *linuxNodeHandler {
	return &linuxNodeHandler{
		log:          hivetest.Logger(t),
		nodeMap:      fakenodemap.NewFakeNodeMapV2(),
		nodeIDs:      idpool.NewIDPool(minID, maxID),
		nodeIDsByIPs: map[string]uint16{},
		nodeIPsByIDs: map[uint16]sets.Set[string]{},
	}
}

func testNode(ips ...string) *nodeTypes.Node {
	n := &nodeTypes.Node{Name: "test-node"}
	for _, ip := range ips {
		n.IPAddresses = append(n.IPAddresses, nodeTypes.Address{IP: net.ParseIP(ip)})
	}
	return n
}

// TestNodeIDLeakOnSharedRouterIP reproduces
// https://github.com/cilium/cilium/issues/47563: when a node ID gets
// orphaned by allocateIDForNode's inconsistent-mapping recovery path (which
// can happen when a router IP is shared across nodes' IPAddresses, e.g. a
// shared --local-router-ipv4), the ID must be returned to the free pool. If
// it isn't, the pool is silently exhausted over time even though far fewer
// node IDs are actually in use.
func TestNodeIDLeakOnSharedRouterIP(t *testing.T) {
	const routerIP = "169.254.2.1"

	// Only 2 IDs available: this makes exhaustion trivially observable.
	n := newTestNodeIDHandler(t, 1, 2)

	// Node A gets a node ID for its own IP plus the shared router IP.
	nodeA := testNode("10.0.0.1", routerIP)
	idA, err := n.allocateIDForNode(nil, nodeA)
	require.NoError(t, err)

	// Node B's IP gets an ID first on its own (e.g. via the ipcache path
	// mentioned in allocateIDForNode's doc comment, before the full Node
	// object with the router IP is processed). This consumes the pool's
	// last remaining ID.
	nodeBPartial := testNode("10.0.0.2")
	idB, err := n.allocateIDForNode(nil, nodeBPartial)
	require.NoError(t, err)
	require.NotEqual(t, idA, idB, "node A and B must not share an ID at this point")

	// Now the full node B event arrives, including the shared router IP,
	// which already has id A's ID. This is the inconsistent-mapping case:
	// node B's own IP has idB, but the router IP resolves to idA.
	nodeBFull := testNode("10.0.0.2", routerIP)
	newIDB, err := n.allocateIDForNode(nil, nodeBFull)

	// The recovery path unmaps node B's stale mapping and allocates a fresh
	// ID for it. That must succeed - the pool must not have been silently
	// exhausted by the now-orphaned original idB, even though there are
	// only 2 IDs in the entire pool and node A is still using one of them.
	require.NoError(t, err, "re-allocating node B's ID should succeed: the orphaned ID must have been freed")
	require.NotEqual(t, uint16(0), newIDB)

	// Sanity check: node A's mapping must be completely unaffected.
	got, ok := n.nodeIDsByIPs["10.0.0.1"]
	require.True(t, ok)
	require.Equal(t, idA, got)
}
