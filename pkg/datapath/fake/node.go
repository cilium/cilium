// Copyright 2018-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fake

import (
	"context"

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

func (n *fakeNodeHandler) NodeCleanNeighbors() {
	return
}
