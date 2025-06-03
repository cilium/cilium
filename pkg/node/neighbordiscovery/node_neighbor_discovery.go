// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbordiscovery

import (
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/neighbor"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var Cell = cell.Module(
	"node-neighbor-discovery",
	"A node handler that manages forwardable IPs for nodes in the cluster",
	cell.Invoke(NewNodeNeighborHandler),
)

var (
	_ datapath.NodeHandler             = (*nodeNeighborHandler)(nil)
	_ datapath.NodeConfigChangeHandler = (*nodeNeighborHandler)(nil)
)

// NewNodeNeighborHandler initializes the node neighbor handler and
// subscribes it to the node manager if L2 neighbor discovery is enabled.
// It will add forwardable IPs for all nodes in the cluster to the
func NewNodeNeighborHandler(
	nodeManger manager.NodeManager,
	forwardableIPManager *neighbor.ForwardableIPManager,
	nodeConfigNotifier *manager.NodeConfigNotifier,
) {
	// If the forwardable IP manager is not enabled, then there is no point to
	// doing any work here.
	if !forwardableIPManager.Enabled() {
		return
	}

	nnh := &nodeNeighborHandler{
		forwardableIPManager: forwardableIPManager,
		initializer:          forwardableIPManager.RegisterInitializer("node-neighbor-discovery"),
	}

	nodeManger.Subscribe(nnh)
	nodeConfigNotifier.Subscribe(nnh)
}

type nodeNeighborHandler struct {
	forwardableIPManager *neighbor.ForwardableIPManager
	initializer          neighbor.ForwardableIPInitializer
}

// Name identifies the handler, this is used in logging/reporting handler
// reconciliation errors.
func (nnh *nodeNeighborHandler) Name() string {
	return "node-neighbor-handler"
}

// NodeAdd is called when a node is discovered for the first time.
func (nnh *nodeNeighborHandler) NodeAdd(newNode nodeTypes.Node) error {
	// We only want to add forwardable IPs for nodes that are not local.
	if newNode.IsLocal() {
		return nil
	}

	if newNode.GetNodeIP(false).To4() != nil {
		ipv4, ok := netip.AddrFromSlice(newNode.GetNodeIP(false).To4())
		if ok {
			err := nnh.forwardableIPManager.Insert(
				ipv4,
				neighbor.ForwardableIPOwner{
					Type: neighbor.ForwardableIPOwnerNode,
					ID:   newNode.Identity().String(),
				},
			)
			if err != nil {
				return fmt.Errorf("failed to insert forwardable IP for node %s: %w", newNode.Name, err)
			}
		}
	}

	if newNode.GetNodeIP(true).To16() != nil {
		ipv4, ok := netip.AddrFromSlice(newNode.GetNodeIP(true).To16())
		if ok {
			err := nnh.forwardableIPManager.Insert(
				ipv4,
				neighbor.ForwardableIPOwner{
					Type: neighbor.ForwardableIPOwnerNode,
					ID:   newNode.Identity().String(),
				},
			)
			if err != nil {
				return fmt.Errorf("failed to insert forwardable IP for node %s: %w", newNode.Name, err)
			}
		}
	}

	return nil
}

// NodeUpdate is called when a node definition changes. Both the old
// and new node definition is provided. NodeUpdate() is never called
// before NodeAdd() is called for a particular node.
func (nnh *nodeNeighborHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	// We only want to add forwardable IPs for nodes that are not local.
	if oldNode.IsLocal() {
		return nil
	}

	// We only care if the node name or IP address has changed.
	if oldNode.Identity().String() != newNode.Identity().String() ||
		!oldNode.GetNodeIP(false).To4().Equal(newNode.GetNodeIP(false).To4()) ||
		!oldNode.GetNodeIP(false).To16().Equal(newNode.GetNodeIP(false).To16()) {

		if err := nnh.NodeDelete(oldNode); err != nil {
			return fmt.Errorf("failed to delete old node %s: %w", oldNode.Name, err)
		}

		if err := nnh.NodeAdd(newNode); err != nil {
			return fmt.Errorf("failed to add new node %s: %w", newNode.Name, err)
		}
	}

	return nil
}

// NodeDelete is called after a node has been deleted
func (nnh *nodeNeighborHandler) NodeDelete(node nodeTypes.Node) error {
	// We only want to add forwardable IPs for nodes that are not local.
	if node.IsLocal() {
		return nil
	}

	if node.GetNodeIP(false).To4() != nil {
		ipv4, ok := netip.AddrFromSlice(node.GetNodeIP(false).To4())
		if ok {
			err := nnh.forwardableIPManager.Delete(
				ipv4,
				neighbor.ForwardableIPOwner{
					Type: neighbor.ForwardableIPOwnerNode,
					ID:   node.Name,
				},
			)
			if err != nil {
				return fmt.Errorf("failed to delete forwardable IP for node %s: %w", node.Name, err)
			}
		}
	}

	if node.GetNodeIP(false).To16() != nil {
		ipv4, ok := netip.AddrFromSlice(node.GetNodeIP(false).To16())
		if ok {
			err := nnh.forwardableIPManager.Insert(
				ipv4,
				neighbor.ForwardableIPOwner{
					Type: neighbor.ForwardableIPOwnerNode,
					ID:   node.Name,
				},
			)
			if err != nil {
				return fmt.Errorf("failed to delete forwardable IP for node %s: %w", node.Name, err)
			}
		}
	}

	return nil
}

// AllNodeValidateImplementation is called to validate the implementation
// of all nodes in the node cache.
func (nnh *nodeNeighborHandler) AllNodeValidateImplementation() {
	// This is a no-op for the node neighbor handler.
}

// NodeValidateImplementation is called to validate the implementation of
// the node in the datapath. This function is intended to be run on an
// interval to ensure that the datapath is consistently converged.
func (nnh *nodeNeighborHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	// We only want to add forwardable IPs for nodes that are not local.
	if node.IsLocal() {
		return nil
	}

	// [nodeNeighborHandler.NodeAdd] is idempotent, so a forwardable IP already exists
	// this is a no-op. If the forwardable IP does not exist, it will be created.
	return nnh.NodeAdd(node)
}

// NodeConfigurationChanged is called when the local node configuration
// has changed
func (nnh *nodeNeighborHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {

	// `NodeConfigurationChanged` is called by the loader when the datapath is initialized.
	// We use this event as a signal that `NodeAdd` should have been called for all nodes
	// we should know about and that we can consider our entries in the forwardable IP manager
	// as initialized.
	nnh.forwardableIPManager.FinishInitializer(nnh.initializer)

	return nil
}
