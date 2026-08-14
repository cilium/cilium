// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
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

type failOnceNodeMap struct {
	nodemap.MapV2
	fail bool
}

func (m *failOnceNodeMap) Update(ip netip.Addr, nodeID uint16, spi uint8) error {
	if m.fail {
		m.fail = false
		return fmt.Errorf("update failed")
	}
	return m.MapV2.Update(ip, nodeID, spi)
}

func newTestLinuxNodeOps(t *testing.T) (*linuxNodeHandler, *linuxNodeOps) {
	t.Helper()
	handler := newNodeHandler(
		hivetest.Logger(t),
		DatapathConfiguration{},
		nodemapfake.NewFakeNodeMapV2(),
		kpr.KPRConfig{},
		&fakeipsec.Agent{},
		fakeipsec.Config{},
		node.NewTestLocalNodeStore(node.LocalNode{}),
	)
	handler.enableEncapsulation = func(*nodeTypes.Node) bool { return false }
	return handler, &linuxNodeOps{handler: handler}
}

func TestLinuxNodeOpsWaitsForConfiguration(t *testing.T) {
	_, ops := newTestLinuxNodeOps(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := ops.Update(ctx, nil, 0, &node.Node{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestLinuxNodeOpsUpdateAndDelete(t *testing.T) {
	handler, ops := newTestLinuxNodeOps(t)
	handler.isInitialized = true
	close(handler.configReady)

	n := &node.Node{Node: nodeTypes.Node{
		Name:    "node-1",
		Cluster: "cluster-1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("192.0.2.1"),
		}},
	}}

	require.NoError(t, ops.Update(t.Context(), nil, statedb.Revision(1), n))
	stored, found := handler.nodes[n.Identity()]
	require.True(t, found)
	require.True(t, stored.DeepEqual(&n.Node))

	require.NoError(t, ops.Delete(t.Context(), nil, statedb.Revision(2), n))
	_, found = handler.nodes[n.Identity()]
	require.False(t, found)
	require.Empty(t, handler.nodeIDsByIPs)
}

func TestLinuxNodeOpsRetriesFailedUpdate(t *testing.T) {
	handler, ops := newTestLinuxNodeOps(t)
	handler.isInitialized = true
	close(handler.configReady)
	handler.nodeMap = &failOnceNodeMap{
		MapV2: nodemapfake.NewFakeNodeMapV2(),
		fail:  true,
	}
	handler.nodeIDs = idpool.NewIDPool(1, 1)

	n := &node.Node{Node: nodeTypes.Node{
		Name:    "node-1",
		Cluster: "cluster-1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("192.0.2.1"),
		}},
	}}

	require.Error(t, ops.Update(t.Context(), nil, statedb.Revision(1), n))
	require.Contains(t, handler.pendingNodes, n.Identity())
	require.NotContains(t, handler.nodes, n.Identity())

	require.NoError(t, ops.Update(t.Context(), nil, statedb.Revision(2), n))
	require.NotContains(t, handler.pendingNodes, n.Identity())
	require.Equal(t, uint16(minNodeID), handler.nodeIDsByIPs["192.0.2.1"])
}
