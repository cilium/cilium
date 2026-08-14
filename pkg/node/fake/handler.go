// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"
	"net"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

// Observe mirrors the node table into the fake handler for control-plane
// tests that inspect realized nodes.
func (n *Handler) Observe(ctx context.Context, db *statedb.DB, nodes statedb.Table[*node.Node]) error {
	for {
		txn := db.ReadTxn()
		all, watch := nodes.AllWatch(txn)
		current := map[string]types.Node{}
		for obj := range all {
			current[obj.Name] = obj.Node
		}

		n.mu.Lock()
		n.Nodes = current
		n.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

type Handler struct {
	mu    lock.Mutex
	Nodes map[string]types.Node
}

func (n *Handler) GetNodeID(_ net.IP) (uint16, bool) {
	return 0, true
}

// NewHandler returns a fake NodeHandler that stores the nodes,
// but performs no other actions.
func NewHandler() *Handler {
	return &Handler{Nodes: make(map[string]types.Node)}
}

func (n *Handler) Name() string {
	return "fake-node-handler"
}

func (n *Handler) NodeAdd(newNode types.Node) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[newNode.Name] = newNode
	return nil
}

func (n *Handler) NodeUpdate(oldNode, newNode types.Node) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes[newNode.Name] = newNode
	return nil
}

func (n *Handler) NodeDelete(node types.Node) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.Nodes, node.Name)
	return nil
}

func (n *Handler) AllNodeValidateImplementation() {
}

func (n *Handler) NodeValidateImplementation(node types.Node) error {
	return nil
}

func (n *Handler) GetNodeIP(_ uint16) string {
	return ""
}

func (n *Handler) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (n *Handler) RestoreNodeIDs() {
}
