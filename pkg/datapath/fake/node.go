// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2021 Authors of Cilium

package fake

import (
	"context"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type FakeNodeHandler struct{}

// NewNodeHandler returns a fake NodeHandler that performs no actions
func NewNodeHandler() *FakeNodeHandler {
	return &FakeNodeHandler{}
}

func (n *FakeNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	return nil
}

func (n *FakeNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	return nil
}

func (n *FakeNodeHandler) NodeDelete(node nodeTypes.Node) error {
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

func (n *FakeNodeHandler) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (n *FakeNodeHandler) RestoreNodeIDs() {
	return
}
