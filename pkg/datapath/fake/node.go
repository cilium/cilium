// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type FakeNodeHandler struct {
	Nodes map[string]nodeTypes.Node
}

// NewNodeHandler returns a fake NodeHandler that stores the nodes,
// but performs no other actions.
func NewNodeHandler() *FakeNodeHandler {
	return &FakeNodeHandler{Nodes: make(map[string]nodeTypes.Node)}
}

func (n *FakeNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	n.Nodes[newNode.Name] = newNode
	return nil
}

func (n *FakeNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	n.Nodes[newNode.Name] = newNode
	return nil
}

func (n *FakeNodeHandler) NodeDelete(node nodeTypes.Node) error {
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
