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

// isFirstNodeUpdate tracks the first node update to the endpoint manager.
// This is used to resolve a race condition during agent startup where the
// k8s node label updates are rejected indefinitely by the host endpoint (GH-29649).
var isFirstNodeUpdate = true

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
// from K8s.
// This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnAddNode(newNode *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {
	return mgr.OnUpdateNode(nil, newNode, swg)
}

// OnUpdateNode implements the endpointManager's logic for reacting to updated
// nodes in K8s.
// This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnUpdateNode(oldNode, newNode *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	var oldNodeLabels map[string]string
	// Endpoint's label update logic rejects a request if any of the old labels are
	// not present in the endpoint manager's state. Overwrite the old labels to nil
	// for the first node update to avoid node labels being outdated indefinitely (GH-29649).
	if oldNode == nil || isFirstNodeUpdate {
		oldNodeLabels = make(map[string]string)
	} else {
		oldNodeLabels = oldNode.GetLabels()
	}
	newNodeLabels := newNode.GetLabels()
	// Set the labels early so host endpoint is created with latest labels.
	node.SetLabels(newNodeLabels)

	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		log.Debug("Host endpoint not found")
		return nil
	}

	if err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s); err != nil {
		log.WithError(err).Error("Unable to update host endpoint labels")
		return err
	}
	// Set isFirstNodeUpdate to false only on successful update.
	isFirstNodeUpdate = false

	return nil
}

// OnDeleteNode implements the endpointManager's logic for reacting to node
// deletions from K8s. It is currently not implemented as the endpointManager
// has not need for it. This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnDeleteNode(node *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	return nil
}
