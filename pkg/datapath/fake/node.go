// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type fakeNodeHandler struct{}

// NewNodeHandler returns a fake NodeHandler that performs no actions
func NewNodeHandler() *fakeNodeHandler {
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

func (n *fakeNodeHandler) AllNodeValidateImplementation() {
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

func (n *fakeNodeHandler) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (n *fakeNodeHandler) RestoreNodeIDs() {
	return
}
