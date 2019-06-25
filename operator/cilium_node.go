// Copyright 2019 Authors of Cilium
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

package main

import (
	"reflect"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"

	"k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var ciliumNodeStore cache.Store

func convertToCiliumNode(obj interface{}) interface{} {
	cnp, _ := obj.(*v2.CiliumNode)
	return cnp
}

func startSynchronizingCiliumNodes() {
	log.Info("Starting to synchronize CiliumNode custom resources...")

	// TODO: The operator is currently storing a full copy of the
	// CiliumNode resource, as the resource grows, we may want to consider
	// introducing a slim version of it.
	ciliumNodeStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, fields.Everything()),
		&v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node, ok := obj.(*v2.CiliumNode); ok {
					_, err := k8s.Client().CoreV1().Nodes().Get(node.Name, metav1.GetOptions{})
					switch {
					case k8serrors.IsNotFound(err):
						log.WithField("name", node.Name).Warning("Discovered CiliumNode without matching Kubernetes node resource")
						deleteCiliumNode(node.Name)
						return
					case err != nil:
						log.WithField("name", node.Name).WithError(err).Warning("Unable to retrieve Kubernetes node")
					}

					ciliumNodeUpdated(node.DeepCopy())
				} else {
					log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node, ok := newObj.(*v2.CiliumNode); ok {
					ciliumNodeUpdated(node.DeepCopy())
				} else {
					log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(newObj), newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					// Delete was not observed by the
					// watcher but is removed from
					// kube-apiserver. This is the last
					// known state and the object no longer
					// exists.
					if node, ok := deletedObj.Obj.(*v2.CiliumNode); ok {
						ciliumNodeDeleted(node.Name)
						return
					}
				} else if node, ok := obj.(*v2.CiliumNode); ok {
					ciliumNodeDeleted(node.Name)
					return
				}
				log.Warningf("Unknown CiliumNode object type %s received: %+v", reflect.TypeOf(obj), obj)
			},
		},
		convertToCiliumNode,
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)
}

func deleteCiliumNode(name string) {
	if err := ciliumK8sClient.CiliumV2().CiliumNodes().Delete(name, &metav1.DeleteOptions{}); err == nil {
		log.WithField("name", name).Info("Removed CiliumNode after receiving node deletion event")
	}
	ciliumNodeDeleted(name)
}
