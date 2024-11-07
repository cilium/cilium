// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"fmt"
	"maps"
	"slices"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/lock"
)

// meshNodeInformer uses the remote clusters inside the Cilium mesh to fake nodes
// with the same name as the clusters and the meshPodInformer also use cluster name as
// node name. This trick allows the EndpointSlice controller to set correct
// topology on EndpointSlice objects.
type meshNodeInformer struct {
	dummyInformer

	handler cache.ResourceEventHandler
	nodes   map[string]*v1.Node
	mutex   lock.RWMutex
}

func newMeshNodeInformer(logger logrus.FieldLogger) *meshNodeInformer {
	return &meshNodeInformer{
		dummyInformer: dummyInformer{name: "meshNodeInformer", logger: logger},
		nodes:         map[string]*v1.Node{},
	}
}

func createDummyNode(cluster string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   cluster,
			Labels: map[string]string{v1.LabelTopologyZone: cluster},
		},
		Status: v1.NodeStatus{
			Phase: v1.NodeRunning,
			Conditions: []v1.NodeCondition{
				{Type: v1.NodeReady, Status: v1.ConditionTrue},
			},
			// Set to 1 cpu per "node"/cluster so that topology manager will set the topology.
			// This could be improved later on with meaningful value for weighted traffic distribution
			// with kube-proxy enabled
			Allocatable: v1.ResourceList{v1.ResourceCPU: *resource.NewQuantity(1, resource.DecimalSI)},
		},
	}
}

func (i *meshNodeInformer) ListClusters() []string {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	return slices.Collect(maps.Keys(i.nodes))
}

func (i *meshNodeInformer) List(selector labels.Selector) ([]*v1.Node, error) {
	reqs, _ := selector.Requirements()
	if !selector.Empty() {
		return nil, fmt.Errorf("meshNodeInformer only supports listing everything as requirements: %s", reqs)
	}

	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return slices.Collect(maps.Values(i.nodes)), nil
}

func (i *meshNodeInformer) Get(name string) (*v1.Node, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	if node, ok := i.nodes[name]; ok {
		return node, nil
	}
	return nil, newNotFoundError(fmt.Sprintf("node '%s' not found", name))
}

func (i *meshNodeInformer) onClusterAdd(cluster string) {
	i.mutex.Lock()
	node := createDummyNode(cluster)
	i.nodes[cluster] = node
	i.mutex.Unlock()

	if i.handler == nil {
		return
	}
	i.handler.OnAdd(node, false)
}

func (i *meshNodeInformer) onClusterDelete(cluster string) {
	i.mutex.Lock()
	delete(i.nodes, cluster)
	i.mutex.Unlock()

	if i.handler == nil {
		return
	}
	i.handler.OnDelete(i.nodes[cluster])
}

func (i *meshNodeInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = handler
	return i, nil
}

func (i *meshNodeInformer) HasSynced() bool {
	// Controller is launched only after cluster mesh has been fully synced
	// so we always return true here
	return true
}

func (i *meshNodeInformer) Informer() cache.SharedIndexInformer {
	return i
}
func (i *meshNodeInformer) Lister() listersv1.NodeLister {
	return i
}
