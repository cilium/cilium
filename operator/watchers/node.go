// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

type slimNodeGetter interface {
	GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error)
}

// nodeGetter reads Kubernetes nodes from a synchronized resource store.
//
// The returned structures are shared with every other reader of the store and
// must never be written to.
type nodeGetter struct {
	store resource.Store[*slim_corev1.Node]
}

// GetK8sSlimNode returns a slim_corev1.Node from the local store.
func (g nodeGetter) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	node, exists, err := g.store.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(slim_corev1.Resource("nodes"), nodeName)
	}
	return node, nil
}
