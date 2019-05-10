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
	"context"
	"time"

	"github.com/cilium/cilium/pkg/controller"
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

	ciliumNodeStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	ciliumNodeInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			"ciliumnodes", v1.NamespaceAll, fields.Everything()),
		&v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if node, ok := obj.(*v2.CiliumNode); ok {
					log.Debugf("Received new CiliumNode %+v", node)

					_, err := k8s.Client().CoreV1().Nodes().Get(node.Name, metav1.GetOptions{})
					switch {
					case k8serrors.IsNotFound(err):
						log.Warningf("Discovered CiliumNode %s without matching Kubernetes node resource", node.Name)
						deleteCiliumNode(node.Name)
						return
					case err != nil:
						log.WithError(err).Warningf("Unable to retrieve Kubernetes node %s", node.Name)
					}

					ciliumNodeUpdated(node)
				} else {
					log.Warningf("Unknown CiliumNode object received: %+v", obj)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if node, ok := newObj.(*v2.CiliumNode); ok {
					log.Debugf("Received updated CiliumNode %+v", node)
					ciliumNodeUpdated(node)
				} else {
					log.Warningf("Unknown CiliumNode object received: %+v", newObj)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if node, ok := obj.(*v2.CiliumNode); ok {
					log.Debugf("CiliumNode got deleted %+v", node)
					ciliumNodeDeleted(node.Name)
				} else {
					log.Warningf("Unknown CiliumNode object received: %+v", obj)
				}
			},
		},
		convertToCiliumNode,
		ciliumNodeStore,
	)

	go ciliumNodeInformer.Run(wait.NeverStop)

	// Delay start of the CiliumNode garbage collector
	go func() {
		time.Sleep(time.Minute * 2)
		controller.NewManager().UpdateController("remove-stale-cilium-nodes",
			controller.ControllerParams{
				RunInterval: time.Minute * 30,
				DoFunc: func(ctx context.Context) error {
					client := k8s.Client()
					for _, nodeName := range nodeManager.GetNames() {
						_, err := client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
						switch {
						case k8serrors.IsNotFound(err):
							deleteCiliumNode(nodeName)
						case err != nil:
							log.WithError(err).Warningf("Unable to retrieve Kubernetes node %s", nodeName)
						}
					}
					return nil
				},
			})
	}()
}

func deleteCiliumNode(name string) {
	if err := ciliumK8sClient.CiliumV2().CiliumNodes("default").Delete(name, &metav1.DeleteOptions{}); err == nil {
		log.Infof("Removed CiliumNode %s after receiving node deletion event", name)
	}
	ciliumNodeDeleted(name)
}
