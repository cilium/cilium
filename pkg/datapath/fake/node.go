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

type fakeNodeHandler struct{}

// NewNodeHandler returns a fake NodeHandler that performs no actions
func NewNodeHandler() datapath.NodeHandler {
	return &fakeNodeHandler{}
}

func (n *fakeNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	return nil
}

func (n *fakeNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	return nil
}

func (n *fakeNodeHandler) NodeDelete(node nodeTypes.Node) error {
	return nil
}

func (n *fakeNodeHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	return nil
}

func (n *fakeNodeHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	return nil
}

func (n *fakeNodeHandler) NodeNeighDiscoveryEnabled() bool {
	return false
}

func (n *fakeNodeHandler) NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node) {
	return
}

func (n *fakeNodeHandler) NodeCleanNeighbors(migrateOnly bool) {
	return
}

func (n *fakeNodeHandler) AllocateNodeID(_ net.IP) uint16 {
	return 0
}

func (n *fakeNodeHandler) DumpNodeIDs() []*models.NodeID {
	return nil
}
