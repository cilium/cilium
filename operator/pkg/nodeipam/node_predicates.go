// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeipam

import v1 "k8s.io/api/core/v1"

const (
	// ToBeDeletedTaint is a taint used by the Cluster Autoscaler before marking a node for deletion. Defined in
	// https://github.com/kubernetes/autoscaler/blob/e80ab518340f88f364fe3ef063f8303755125971/cluster-autoscaler/utils/deletetaint/delete.go#L36
	toBeDeletedTaint = "ToBeDeletedByClusterAutoscaler"
)

// shouldIncludeNode matches the stableNodeSetPredicates in the
// kubernetes/cloud-provider project as described by KEP-3458, see the link below.
// https://github.com/kubernetes/cloud-provider/blob/d7d37dea2df950e8cdf156bcf9fc0e32f6540ad5/controllers/service/controller.go#L1015
func shouldIncludeNode(node *v1.Node) bool {
	return nodeNotDeletedPredicate(node) &&
		nodeIncludedPredicate(node) &&
		nodeUnTaintedPredicate(node)
}

func nodeNotDeletedPredicate(node *v1.Node) bool {
	return node.DeletionTimestamp.IsZero()
}

// We consider the node for load balancing only when the node is not labelled for exclusion.
func nodeIncludedPredicate(node *v1.Node) bool {
	_, hasExcludeBalancerLabel := node.Labels[v1.LabelNodeExcludeBalancers]
	return !hasExcludeBalancerLabel
}

// We consider the node for load balancing only when it is not tainted for deletion by the cluster autoscaler.
func nodeUnTaintedPredicate(node *v1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Key == toBeDeletedTaint {
			return false
		}
	}
	return true
}
