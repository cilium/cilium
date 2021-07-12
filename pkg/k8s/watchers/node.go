// Copyright 2020-2021 Authors of Cilium
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

package watchers

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	// onceNodeInitStart is used to guarantee that only one function call of
	// NodesInit is executed.
	onceNodeInitStart sync.Once
)

// NodesInit initializes a k8s watcher for node events belonging to the node
// where Cilium is running.
func (k *K8sWatcher) NodesInit(k8sClient *k8s.K8sClient) {
	onceNodeInitStart.Do(func() {
		nodeStore, nodeController := informer.NewInformer(
			cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
				"nodes", v1.NamespaceAll, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName())),
			&v1.Node{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid bool
					if node := k8s.ObjToV1Node(obj); node != nil {
						valid = true
						if hasAgentNotReadyTaint(node) || !k8s.HasCiliumIsUpCondition(node) {
							k8sClient.ReMarkNodeReady()
						}
						err := k.updateK8sNodeV1(nil, node)
						k.K8sEventProcessed(metricNode, metricCreate, err == nil)
					}
					k.K8sEventReceived(metricNode, metricCreate, valid, false)
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					if oldNode := k8s.ObjToV1Node(oldObj); oldNode != nil {
						valid = true
						if newNode := k8s.ObjToV1Node(newObj); newNode != nil {
							if hasAgentNotReadyTaint(newNode) || !k8s.HasCiliumIsUpCondition(newNode) {
								k8sClient.ReMarkNodeReady()
							}

							oldNodeLabels := oldNode.GetLabels()
							newNodeLabels := newNode.GetLabels()
							if comparator.MapStringEquals(oldNodeLabels, newNodeLabels) {
								equal = true
							} else {
								err := k.updateK8sNodeV1(oldNode, newNode)
								k.K8sEventProcessed(metricNode, metricUpdate, err == nil)
							}
						}
					}
					k.K8sEventReceived(metricNode, metricUpdate, valid, equal)
				},
			},
			nil,
		)

		k.nodeStore = nodeStore

		k.blockWaitGroupToSyncResources(wait.NeverStop, nil, nodeController.HasSynced, k8sAPIGroupNodeV1Core)
		go nodeController.Run(wait.NeverStop)
		k.k8sAPIGroups.AddAPI(k8sAPIGroupNodeV1Core)
	})
}

// hasAgentNotReadyTaint returns true if the given node has the Cilium Agen
// Not Ready Node Taint.
func hasAgentNotReadyTaint(k8sNode *v1.Node) bool {
	for _, taint := range k8sNode.Spec.Taints {
		if taint.Key == ciliumio.AgentNotReadyNodeTaint {
			return true
		}
	}
	return false
}

func (k *K8sWatcher) updateK8sNodeV1(oldK8sNode, newK8sNode *v1.Node) error {
	var oldNodeLabels map[string]string
	if oldK8sNode != nil {
		oldNodeLabels = oldK8sNode.GetLabels()
	}
	newNodeLabels := newK8sNode.GetLabels()

	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateNode(newK8sNode)
	}

	nodeEP := k.endpointManager.GetHostEndpoint()
	if nodeEP == nil {
		log.Debug("Host endpoint not found, updating node labels")
		node.SetLabels(newNodeLabels)
		return nil
	}

	err := updateEndpointLabels(nodeEP, oldNodeLabels, newNodeLabels)
	if err != nil {
		return err
	}
	return nil
}

// GetK8sNode returns the *local Node* from the local store.
func (k *K8sWatcher) GetK8sNode(_ context.Context, nodeName string) (*v1.Node, error) {
	k.WaitForCacheSync(k8sAPIGroupNodeV1Core)
	pName := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
	}
	nodeInterface, exists, err := k.nodeStore.Get(pName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return nodeInterface.(*v1.Node).DeepCopy(), nil
}
