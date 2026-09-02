// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

// Store provides test access to the nodes in StateDB and implements the
// no-op node ID operations used by the fake datapath.
type Store struct {
	db    *statedb.DB
	nodes statedb.Table[*node.Node]
}

// NewStore constructs a fake node store.
func NewStore(db *statedb.DB, nodes statedb.Table[*node.Node]) *Store {
	return &Store{db: db, nodes: nodes}
}

// Nodes returns a snapshot of nodes keyed by node name.
func (s *Store) Nodes() map[string]types.Node {
	nodes := map[string]types.Node{}
	for n := range s.nodes.All(s.db.ReadTxn()) {
		nodes[n.Name] = n.Node
	}
	return nodes
}

func (*Store) GetNodeID(_ net.IP) (uint16, bool) {
	return 0, true
}

func (*Store) GetNodeIP(_ uint16) string {
	return ""
}

func (*Store) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (*Store) RestoreNodeIDs() {
}
