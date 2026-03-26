// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/node/types"
)

// Handler handles node related events such as addition, update or deletion
// of nodes or changes to the local node configuration.
//
// Node events apply to the local node as well as to remote nodes. The
// implementation can differ between the own local node and remote nodes by
// calling node.IsLocal().
type Handler interface {
	// Name identifies the handler, this is used in logging/reporting handler
	// reconciliation errors.
	Name() string

	// NodeAdd is called when a node is discovered for the first time.
	NodeAdd(newNode types.Node) error

	// NodeUpdate is called when a node definition changes. Both the old
	// and new node definition is provided. NodeUpdate() is never called
	// before NodeAdd() is called for a particular node.
	NodeUpdate(oldNode, newNode types.Node) error

	// NodeDelete is called after a node has been deleted
	NodeDelete(node types.Node) error

	// AllNodeValidateImplementation is called to validate the implementation
	// of all nodes in the node cache.
	AllNodeValidateImplementation()

	// NodeValidateImplementation is called to validate the implementation of
	// the node in the datapath. This function is intended to be run on an
	// interval to ensure that the datapath is consistently converged.
	NodeValidateImplementation(node types.Node) error
}

type IDHandler interface {
	// GetNodeIP returns the string node IP that was previously registered as the given node ID.
	GetNodeIP(uint16) string

	// GetNodeID gets the node ID for the given node IP. If none is found, exists is false.
	GetNodeID(nodeIP net.IP) (nodeID uint16, exists bool)

	// DumpNodeIDs returns all node IDs and their associated IP addresses.
	DumpNodeIDs() []*models.NodeID

	// RestoreNodeIDs restores node IDs and their associated IP addresses from the
	// BPF map and into the node handler in-memory copy.
	RestoreNodeIDs()
}
