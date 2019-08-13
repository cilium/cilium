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
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/node"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/source"

	"k8s.io/api/core/v1"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	// kvNodeGCInterval duration for which the nodes are GC in the KVStore.
	kvNodeGCInterval              time.Duration
	enableCNPNodeStatusGC         bool
	ciliumCNPNodeStatusGCInterval time.Duration
)

func runNodeWatcher() error {
	log.Info("Starting to synchronize k8s nodes to kvstore...")

	serNodes := serializer.NewFunctionQueue(1024)

	ciliumNodeStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:     nodeStore.NodeStorePrefix,
		KeyCreator: nodeStore.KeyCreator,
	})
	if err != nil {
		return err
	}

	k8sNodeStore, nodeController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll, fields.Everything()),
		&v1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if n := k8s.CopyObjToV1Node(obj); n != nil {
					serNodes.Enqueue(func() error {
						nodeNew := k8s.ParseNode(n, source.Kubernetes)
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
							newNode := k8s.ParseNode(newNode, source.Kubernetes)
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
					deletedNode := k8s.ParseNode(n, source.Kubernetes)
					ciliumNodeStore.DeleteLocalKey(deletedNode)
					deleteCiliumNode(n.Name)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToNode,
	)
	go nodeController.Run(wait.NeverStop)

	go func() {
		cache.WaitForCacheSync(wait.NeverStop, nodeController.HasSynced)

		serNodes.Enqueue(func() error {
			// Since we serialize all events received from k8s we know that
			// at this point the list in k8sNodeStore should be the source of truth
			// and we need to delete all nodes in the kvNodeStore that are *not*
			// present in the k8sNodeStore.

			if enableENI {
				nodes, err := ciliumK8sClient.CiliumV2().CiliumNodes().List(meta_v1.ListOptions{})
				if err != nil {
					log.WithError(err).Warning("Unable to list CiliumNodes. Won't clean up stale CiliumNodes")
				} else {
					for _, node := range nodes.Items {
						if _, ok, err := k8sNodeStore.GetByKey(node.Name); !ok && err == nil {
							deleteCiliumNode(node.Name)
						}
					}
				}
			}

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
	}()

	go func() {
		if !enableCNPNodeStatusGC {
			return
		}
		parallelRequests := 4
		removeNodeFromCNP := make(chan func(), 50)
		for i := 0; i < parallelRequests; i++ {
			go func() {
				for f := range removeNodeFromCNP {
					f()
				}
			}()
		}
		controller.NewManager().UpdateController("cnp-node-gc",
			controller.ControllerParams{
				RunInterval: ciliumCNPNodeStatusGCInterval,
				DoFunc: func(ctx context.Context) error {
					lastRun := time.Now().Add(-kvNodeGCInterval)
					k8sCapabilities := k8sversion.Capabilities()
					continueID := ""
					wg := sync.WaitGroup{}
					defer wg.Wait()
					kvStoreNodes := ciliumNodeStore.SharedKeysMap()
					for {
						cnpList, err := ciliumK8sClient.CiliumV2().CiliumNetworkPolicies(core_v1.NamespaceAll).List(meta_v1.ListOptions{
							Limit:    10,
							Continue: continueID,
						})
						if err != nil {
							return err
						}

						for _, cnp := range cnpList.Items {
							needsUpdate := false
							nodesToDelete := map[string]cilium_v2.Timestamp{}
							for n, status := range cnp.Status.Nodes {
								kvStoreNodeName := node.GetKeyNodeName(option.Config.ClusterName, n)
								if _, exists := kvStoreNodes[kvStoreNodeName]; !exists {
									// To avoid concurrency issues where a is
									// created and adds its CNP Status before the operator
									// node watcher receives an event that the node
									// was created, we will only delete the node
									// from the CNP Status if the last time it was
									// update was before the lastRun.
									if status.LastUpdated.Before(lastRun) {
										nodesToDelete[n] = status.LastUpdated
										delete(cnp.Status.Nodes, n)
										needsUpdate = true
									}
								}
							}
							if needsUpdate {
								wg.Add(1)
								cnpCpy := cnp.DeepCopy()
								removeNodeFromCNP <- func() {
									updateCNP(ciliumK8sClient.CiliumV2(), cnpCpy, nodesToDelete, k8sCapabilities)
									wg.Done()
								}
							}
						}

						continueID = cnpList.Continue
						if continueID == "" {
							break
						}
					}

					return nil
				},
			})
	}()

	return nil
}

func updateCNP(ciliumClient v2.CiliumV2Interface, cnp *cilium_v2.CiliumNetworkPolicy, nodesToDelete map[string]cilium_v2.Timestamp, capabilities k8sversion.ServerCapabilities) {
	if len(nodesToDelete) == 0 {
		return
	}

	ns := utils.ExtractNamespace(&cnp.ObjectMeta)

	switch {
	case capabilities.Patch:
		var removeStatusNode, remainingStatusNode []k8s.JSONPatch
		for nodeToDelete, timeStamp := range nodesToDelete {
			removeStatusNode = append(removeStatusNode,
				// It is really unlikely to happen but if a node reappears
				// with the same name and updates the CNP Status we will perform
				// a test to verify if the lastUpdated timestamp is the same to
				// to avoid accidentally deleting that node.
				// If any of the nodes fails this test *all* of the JSON patch
				// will not be executed.
				k8s.JSONPatch{
					OP:    "test",
					Path:  "/status/nodes/" + nodeToDelete + "/lastUpdated",
					Value: timeStamp,
				},
				k8s.JSONPatch{
					OP:   "remove",
					Path: "/status/nodes/" + nodeToDelete,
				},
			)
		}
		for {
			if len(removeStatusNode) > k8s.MaxJSONPatchOperations {
				remainingStatusNode = removeStatusNode[k8s.MaxJSONPatchOperations:]
				removeStatusNode = removeStatusNode[:k8s.MaxJSONPatchOperations]
			}

			removeStatusNodeJSON, err := json.Marshal(removeStatusNode)
			if err != nil {
				break
			}

			_, err = ciliumClient.CiliumNetworkPolicies(ns).Patch(cnp.GetName(), types.JSONPatchType, removeStatusNodeJSON, "status")
			if err != nil {
				// We can leave the errors as debug as the GC happens on a best effort
				log.WithError(err).Debug("Unable to PATCH")
			}

			removeStatusNode = remainingStatusNode

			if len(remainingStatusNode) == 0 {
				return
			}
		}
	case capabilities.UpdateStatus:
		// This should be treat is as best effort, we don't care if the
		// UpdateStatus fails.
		_, err := ciliumClient.CiliumNetworkPolicies(ns).UpdateStatus(cnp)
		if err != nil {
			// We can leave the errors as debug as the GC happens on a best effort
			log.WithError(err).Debug("Unable to UpdateStatus with garbage collected nodes")
		}
	default:
		// This should be treat is as best effort, we don't care if the
		// Update fails.
		_, err := ciliumClient.CiliumNetworkPolicies(ns).Update(cnp)
		if err != nil {
			// We can leave the errors as debug as the GC happens on a best effort
			log.WithError(err).Debug("Unable to Update CNP with garbage collected nodes")
		}
	}
}
