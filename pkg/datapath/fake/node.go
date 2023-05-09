// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/lock"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type FakeNodeHandler struct {
	mu    lock.Mutex
	Nodes map[string]nodeTypes.Node
}

// NewNodeHandler returns a fake NodeHandler that stores the nodes,
// but performs no other actions.
func NewNodeHandler() *FakeNodeHandler {
	return &FakeNodeHandler{Nodes: make(map[string]nodeTypes.Node)}
}

func (n *FakeNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[newNode.Name] = newNode
	return nil
}

func (n *FakeNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[newNode.Name] = newNode
	return nil
}

func (n *FakeNodeHandler) NodeDelete(node nodeTypes.Node) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.Nodes, node.Name)
	return nil
}

func (n *FakeNodeHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	return nil
}

func (n *FakeNodeHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	return nil
}

func (n *FakeNodeHandler) NodeNeighDiscoveryEnabled() bool {
	return false
}

func (n *FakeNodeHandler) NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node) {
	return
}

func (n *FakeNodeHandler) NodeCleanNeighbors(migrateOnly bool) {
	return
}

func (n *FakeNodeHandler) AllocateNodeID(_ net.IP) uint16 {
	return 0
}

func (n *FakeNodeHandler) GetNodeIP(_ uint16) string {
	return ""
}

func (n *FakeNodeHandler) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (n *FakeNodeHandler) RestoreNodeIDs() {
	return
}
