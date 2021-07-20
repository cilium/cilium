// Copyright 2021 Authors of Cilium
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

package endpointmanager

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"

	v1 "k8s.io/api/core/v1"
)

// GetHostEndpoint returns the host endpoint.
func (mgr *EndpointManager) GetHostEndpoint() *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	for _, ep := range mgr.endpoints {
		if ep.IsHost() {
			return ep
		}
	}
	return nil
}

// HostEndpointExists returns true if the host endpoint exists.
func (mgr *EndpointManager) HostEndpointExists() bool {
	return mgr.GetHostEndpoint() != nil
}

// OnAddNode implements the EndpointManager's logic for reacting to new nodes
// from K8s. It is currently not implemented as the EndpointManager has not
// need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *EndpointManager) OnAddNode(node *v1.Node) error { return nil }

// OnUpdateNode implements the EndpointManager's logic for reacting to updated
// nodes in K8s. It is currently not implemented as the EndpointManager has not
// need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *EndpointManager) OnUpdateNode(oldNode, newNode *v1.Node) error {
	oldNodeLabels := oldNode.GetLabels()
	newNodeLabels := newNode.GetLabels()

	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		log.Error("Host endpoint not found")
		return nil
	}

	err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s)
	if err != nil {
		return err
	}

	return nil
}

// OnDeleteNode implements the EndpointManager's logic for reacting to node
// deletions from K8s. It is currently not implemented as the EndpointManager
// has not need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *EndpointManager) OnDeleteNode(node *v1.Node) error { return nil }
