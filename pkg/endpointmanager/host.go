// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"github.com/cilium/cilium/pkg/endpoint"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
)

// GetHostEndpoint returns the host endpoint.
func (mgr *endpointManager) GetHostEndpoint() *endpoint.Endpoint {
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
func (mgr *endpointManager) HostEndpointExists() bool {
	return mgr.GetHostEndpoint() != nil
}

// OnAddNode implements the endpointManager's logic for reacting to new nodes
// from K8s. It is currently not implemented as the endpointManager has not
// need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnAddNode(node *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	return nil
}

// OnUpdateNode implements the endpointManager's logic for reacting to updated
// nodes in K8s. It is currently not implemented as the endpointManager has not
// need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnUpdateNode(oldNode, newNode *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	oldNodeLabels := oldNode.GetLabels()
	newNodeLabels := newNode.GetLabels()

	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		log.Error("Host endpoint not found")
		return nil
	}

	node.SetLabels(newNodeLabels)

	err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s)
	if err != nil {
		return err
	}

	return nil
}

// OnDeleteNode implements the endpointManager's logic for reacting to node
// deletions from K8s. It is currently not implemented as the endpointManager
// has not need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnDeleteNode(node *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	return nil
}
