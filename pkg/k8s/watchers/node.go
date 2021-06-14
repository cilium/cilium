// Copyright 2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) nodesInit(k8sClient kubernetes.Interface) {
	_, nodeController := informer.NewInformer(
		cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName())),
		&slim_corev1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid bool
				if node := k8s.ObjToV1Node(obj); node != nil {
					valid = true
					errs := k.NodeSubscribers.NotifyAdd(node)
					k.K8sEventProcessed(metricNode, metricCreate, len(errs) == 0)
				}
				k.K8sEventReceived(metricNode, metricCreate, valid, false)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				if oldNode := k8s.ObjToV1Node(oldObj); oldNode != nil {
					valid = true
					if newNode := k8s.ObjToV1Node(newObj); newNode != nil {
						oldNodeLabels := oldNode.GetLabels()
						newNodeLabels := newNode.GetLabels()
						if comparator.MapStringEquals(oldNodeLabels, newNodeLabels) {
							equal = true
						} else {
							errs := k.NodeSubscribers.NotifyUpdate(oldNode, newNode)
							k.K8sEventProcessed(metricNode, metricUpdate, len(errs) == 0)
						}
					}
				}
				k.K8sEventReceived(metricNode, metricUpdate, valid, equal)
			},
		},
		nil,
	)

	k.blockWaitGroupToSyncResources(wait.NeverStop, nil, nodeController.HasSynced, k8sAPIGroupNodeV1Core)
	go nodeController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupNodeV1Core)
}
