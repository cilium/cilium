// Copyright 2019-2020 Authors of Cilium
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

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func runNodeWatcher(nodeManager *allocator.NodeEventHandler) error {
	log.Info("Starting to synchronize k8s nodes to kvstore")

	ciliumNodeKVStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:     nodeStore.NodeStorePrefix,
		KeyCreator: nodeStore.KeyCreator,
	})
	if err != nil {
		return err
	}

	ciliumNodeStore, nodeController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2().RESTClient(),
			cilium_v2.CNPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
					nodeNew := nodeTypes.ParseCiliumNode(ciliumNode)
					ciliumNodeKVStore.UpdateKeySync(context.TODO(), &nodeNew)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldNode := k8s.ObjToCiliumNode(oldObj); oldNode != nil {
					if newNode := k8s.ObjToCiliumNode(newObj); newNode != nil {
						if oldNode.DeepEqual(newNode) {
							return
						}

						nodeNew := nodeTypes.ParseCiliumNode(newNode)
						ciliumNodeKVStore.UpdateKeySync(context.TODO(), &nodeNew)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				n := k8s.ObjToCiliumNode(obj)
				if n == nil {
					return
				}
				deletedNode := nodeTypes.ParseCiliumNode(n)
				ciliumNodeKVStore.DeleteLocalKey(context.TODO(), &deletedNode)
				deleteCiliumNode(nodeManager, n.Name)
			},
		},
		nil,
	)
	go nodeController.Run(wait.NeverStop)

	go func() {
		cache.WaitForCacheSync(wait.NeverStop, nodeController.HasSynced)

		// Since we processed all events received from k8s we know that
		// at this point the list in ciliumNodeStore should be the source of
		// truth and we need to delete all nodes in the kvNodeStore that are
		// *not* present in the ciliumNodeStore.
		listOfCiliumNodes := ciliumNodeStore.ListKeys()

		kvStoreNodes := ciliumNodeKVStore.SharedKeysMap()
		for _, ciliumNode := range listOfCiliumNodes {
			// The remaining kvStoreNodes are leftovers that need to be GCed
			kvStoreNodeName := nodeTypes.GetKeyNodeName(option.Config.ClusterName, ciliumNode)
			delete(kvStoreNodes, kvStoreNodeName)
		}

		for _, kvStoreNode := range kvStoreNodes {
			// Only delete the nodes that belong to our cluster
			if strings.HasPrefix(kvStoreNode.GetKeyName(), option.Config.ClusterName) {
				ciliumNodeKVStore.DeleteLocalKey(context.TODO(), kvStoreNode)
			}
		}

	}()

	if operatorOption.Config.CNPNodeStatusGCInterval != 0 {
		go runCNPNodeStatusGC("cnp-node-gc", false, ciliumNodeKVStore)
		go runCNPNodeStatusGC("ccnp-node-gc", true, ciliumNodeKVStore)
	}

	return nil
}

// runCNPNodeStatusGC runs the node status garbage collector for cilium network
// policies. The policy corresponds to CiliumClusterwideNetworkPolicy if the clusterwide
// parameter is true and CiliumNetworkPolicy otherwise.
func runCNPNodeStatusGC(name string, clusterwide bool, ciliumNodeStore *store.SharedStore) {
	parallelRequests := 4
	removeNodeFromCNP := make(chan func(), 50)
	for i := 0; i < parallelRequests; i++ {
		go func() {
			for f := range removeNodeFromCNP {
				f()
			}
		}()
	}

	controller.NewManager().UpdateController(name,
		controller.ControllerParams{
			RunInterval: operatorOption.Config.CNPNodeStatusGCInterval,
			DoFunc: func(ctx context.Context) error {
				lastRun := v1.NewTime(v1.Now().Add(-operatorOption.Config.NodesGCInterval))
				continueID := ""
				wg := sync.WaitGroup{}
				defer wg.Wait()

				kvStoreNodes := ciliumNodeStore.SharedKeysMap()
				for {
					var cnpItemsList []cilium_v2.CiliumNetworkPolicy

					if clusterwide {
						ccnpList, err := ciliumK8sClient.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx,
							meta_v1.ListOptions{
								Limit:    10,
								Continue: continueID,
							})
						if err != nil {
							return err
						}

						cnpItemsList = make([]cilium_v2.CiliumNetworkPolicy, 0)
						for _, ccnp := range ccnpList.Items {
							cnpItemsList = append(cnpItemsList, cilium_v2.CiliumNetworkPolicy{
								Status: ccnp.Status,
							})
						}
						continueID = ccnpList.Continue
					} else {
						cnpList, err := ciliumK8sClient.CiliumV2().CiliumNetworkPolicies(core_v1.NamespaceAll).List(ctx,
							meta_v1.ListOptions{
								Limit:    10,
								Continue: continueID,
							})
						if err != nil {
							return err
						}

						cnpItemsList = cnpList.Items
						continueID = cnpList.Continue
					}

					for _, cnp := range cnpItemsList {
						needsUpdate := false
						nodesToDelete := map[string]v1.Time{}
						for n, status := range cnp.Status.Nodes {
							kvStoreNodeName := nodeTypes.GetKeyNodeName(option.Config.ClusterName, n)
							if _, exists := kvStoreNodes[kvStoreNodeName]; !exists {
								// To avoid concurrency issues where a is
								// created and adds its CNP Status before the operator
								// node watcher receives an event that the node
								// was created, we will only delete the node
								// from the CNP Status if the last time it was
								// update was before the lastRun.
								if status.LastUpdated.Before(&lastRun) {
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
								updateCNP(ciliumK8sClient.CiliumV2(), cnpCpy, nodesToDelete)
								wg.Done()
							}
						}
					}

					// Nothing to continue, break from the loop here
					if continueID == "" {
						break
					}
				}

				return nil
			},
		})

}

func updateCNP(ciliumClient v2.CiliumV2Interface, cnp *cilium_v2.CiliumNetworkPolicy, nodesToDelete map[string]v1.Time) {
	if len(nodesToDelete) == 0 {
		return
	}

	ns := utils.ExtractNamespace(&cnp.ObjectMeta)

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

		// If the namespace is empty the policy is the clusterwide policy
		// and not the namespaced CiliumNetworkPolicy.
		if ns == "" {
			_, err = ciliumClient.CiliumClusterwideNetworkPolicies().Patch(context.TODO(),
				cnp.GetName(), types.JSONPatchType, removeStatusNodeJSON, meta_v1.PatchOptions{}, "status")
		} else {
			_, err = ciliumClient.CiliumNetworkPolicies(ns).Patch(context.TODO(),
				cnp.GetName(), types.JSONPatchType, removeStatusNodeJSON, meta_v1.PatchOptions{}, "status")
		}
		if err != nil {
			// We can leave the errors as debug as the GC happens on a best effort
			log.WithError(err).Debug("Unable to PATCH")
		}

		removeStatusNode = remainingStatusNode

		if len(remainingStatusNode) == 0 {
			return
		}
	}
}
