// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
)

// IDHandler provides access to node IDs and their associated IP addresses.
type IDHandler interface {
	// GetNodeIP returns the string node IP that was previously registered as the given node ID.
	GetNodeIP(uint16) string

	// GetNodeID gets the node ID for the given node IP. If none is found, exists is false.
	GetNodeID(nodeIP net.IP) (nodeID uint16, exists bool)

	// DumpNodeIDs returns all node IDs and their associated IP addresses.
	DumpNodeIDs() []*models.NodeID

	// RestoreNodeIDs restores node IDs and their associated IP addresses from the
	// BPF map and into the implementation's in-memory copy.
	RestoreNodeIDs()
}
