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
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/node"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/serializer"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	// kvNodeGCInterval duration for which the nodes are GC in the KVStore.
	kvNodeGCInterval time.Duration
)

func runNodeWatcher() error {
	serNodes := serializer.NewFunctionQueue(1024)

	ciliumNodeStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:     nodeStore.NodeStorePrefix,
		KeyCreator: nodeStore.KeyCreator,
	})
	if err != nil {
		return err
	}

	k8sNodeStore, nodeController := k8s.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll, fields.Everything()),
		&v1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if n := k8s.CopyObjToV1Node(obj); n != nil {
					serNodes.Enqueue(func() error {
						nodeNew := k8s.ParseNode(n, node.FromKubernetes)
						ciliumNodeStore.UpdateKeySync(nodeNew)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldNode := k8s.CopyObjToV1Node(oldObj); oldNode != nil {
					if newNode := k8s.CopyObjToV1Node(newObj); newNode != nil {
						if k8s.EqualV1Node(oldNode, newNode) {
							return
						}

						serNodes.Enqueue(func() error {
							newNode := k8s.ParseNode(newNode, node.FromKubernetes)
							ciliumNodeStore.UpdateKeySync(newNode)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				n := k8s.CopyObjToV1Node(obj)
				if n == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					n = k8s.CopyObjToV1Node(deletedObj.Obj)
					if n == nil {
						return
					}
				}
				serNodes.Enqueue(func() error {
					deletedNode := k8s.ParseNode(n, node.FromKubernetes)
					ciliumNodeStore.DeleteLocalKey(deletedNode)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToNode,
	)
	go nodeController.Run(wait.NeverStop)

	go func() {
		cache.WaitForCacheSync(wait.NeverStop, nodeController.HasSynced)

		controller.NewManager().UpdateController("kvstore-node-gc",
			controller.ControllerParams{
				RunInterval: kvNodeGCInterval,
				DoFunc: func(_ context.Context) error {
					wg := sync.WaitGroup{}
					wg.Add(1)
					serNodes.Enqueue(func() error {
						defer wg.Done()

						// Since we serialize all events received from k8s we know that
						// at this point the list in k8sNodeStore should be the source of truth
						// and we need to delete all nodes in the kvNodeStore that are *not*
						// present in the k8sNodeStore.

						listOfK8sNodes := k8sNodeStore.ListKeys()

						kvStoreNodes := ciliumNodeStore.SharedKeysMap()
						for _, k8sNode := range listOfK8sNodes {
							// The remaining kvStoreNodes are leftovers
							kvStoreNodeName := node.GetKeyNodeName(option.Config.ClusterName, k8sNode)
							delete(kvStoreNodes, kvStoreNodeName)
						}

						for _, kvStoreNode := range kvStoreNodes {
							if strings.HasPrefix(kvStoreNode.GetKeyName(), option.Config.ClusterName) {
								ciliumNodeStore.DeleteLocalKey(kvStoreNode)
							}
						}

						return nil
					}, serializer.NoRetry)
					wg.Wait()
					return nil
				},
			})
	}()

	return nil
}
