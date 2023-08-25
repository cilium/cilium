// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/endpoint"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
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
// from K8s.
// This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnAddNode(newNode *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	node.SetLabels(newNode.GetLabels())
	node.SetAnnotations(newNode.GetAnnotations())

	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		// if host endpoint does not exist yet, labels will be set when it'll be created.
		return nil
	}

	newLabels := labels.Map2Labels(newNode.GetLabels(), labels.LabelSourceK8s)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	nodeEP.UpdateLabels(context.TODO(), newIdtyLabels, nil, false)

	return nil
}

// OnUpdateNode implements the endpointManager's logic for reacting to updated
// nodes in K8s.
// This adheres to the subscriber.NodeHandler interface.
func (mgr *endpointManager) OnUpdateNode(oldNode, newNode *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	oldNodeLabels := oldNode.GetLabels()
	newNodeLabels := newNode.GetLabels()

	oldNodeAnnotations := oldNode.GetAnnotations()
	newNodeAnnotations := newNode.GetAnnotations()

	labelsEqual := comparator.MapStringEquals(oldNodeLabels, newNodeLabels)
	annotationsEqual := comparator.MapStringEquals(oldNodeAnnotations, newNodeAnnotations)

	// if labels have changed we need to recompute security ID.
	if !labelsEqual {
		nodeEP := mgr.GetHostEndpoint()
		if nodeEP == nil {
			log.Error("Host endpoint not found")
			return nil
		}
		err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s)
		if err != nil {
			return err
		}
	}

	// Perform a SetMultiAttributes if both labels and annotations has changed,
	// since these Set operations will wake up Observers on LocalNodeStore its
	// better to perform one update if multiple attributes change.
	if !labelsEqual && !annotationsEqual {
		node.SetMultiAttributes(func(n *node.LocalNode) {
			n.Labels = newNodeLabels
			n.Annotations = newNodeAnnotations
		})
	} else if !labelsEqual {
		node.SetLabels(newNodeLabels)
	} else if !annotationsEqual {
		node.SetAnnotations(newNodeAnnotations)
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
