// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

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

var (
	// ciliumNodeStore contains all CiliumNodes present in k8s.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced = make(chan struct{})
)

func startSynchronizingCiliumNodes(nodeManager allocator.NodeEventHandler, withKVStore bool) error {
	var (
		resourceEventHandler  = cache.ResourceEventHandlerFuncs{}
		ciliumNodeConvertFunc = k8s.ConvertToCiliumNode
	)

	if withKVStore {
		log.Info("Starting to synchronize CiliumNode custom resources to KVStore")

		ciliumNodeKVStore, err := store.JoinSharedStore(store.Configuration{
			Prefix:     nodeStore.NodeStorePrefix,
			KeyCreator: nodeStore.KeyCreator,
		})
		if err != nil {
			return err
		}

		// Start a go routine to GC all CiliumNodes from the KVStore that are
		// no longer running.
		go func() {
			<-k8sCiliumNodesCacheSynced
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

		// nodeManager is nil so we don't need to handle any events managed by
		// the nodeManager and the events from Kubernetes will only be relevant
		// for KVStore.
		if nodeManager == nil {
			resourceEventHandler = cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						nodeNew := nodeTypes.ParseCiliumNode(ciliumNode)
						ciliumNodeKVStore.UpdateKeySync(context.TODO(), &nodeNew)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
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
						} else {
							log.Warningf("Unknown CiliumNode object type %T received: %+v", newNode, newNode)
						}
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
					}
				},
				DeleteFunc: func(obj interface{}) {
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						deletedNode := nodeTypes.ParseCiliumNode(ciliumNode)
						ciliumNodeKVStore.DeleteLocalKey(context.TODO(), &deletedNode)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
					}
				},
			}
		} else {
			// nodeManager not nil thus the events will be processed by
			// ciliumNodeKVStore and the nodeManager
			resourceEventHandler = cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						nodeNew := nodeTypes.ParseCiliumNode(ciliumNode)
						ciliumNodeKVStore.UpdateKeySync(context.TODO(), &nodeNew)
						// node is deep copied before it is stored in pkg/aws/eni
						nodeManager.Create(ciliumNode)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
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
							// node is deep copied before it is stored in pkg/aws/eni
							nodeManager.Update(newNode)
						} else {
							log.Warningf("Unknown CiliumNode object type %T received: %+v", newNode, newNode)
						}
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
					}
				},
				DeleteFunc: func(obj interface{}) {
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						deletedNode := nodeTypes.ParseCiliumNode(ciliumNode)
						ciliumNodeKVStore.DeleteLocalKey(context.TODO(), &deletedNode)
						nodeManager.Delete(ciliumNode.Name)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
					}
				},
			}
		}

	} else {
		log.Info("Starting to synchronize CiliumNode custom resources")
		if nodeManager == nil {
			// Both nodeManager and KVStore are nil. We don't need to handle
			// any watcher events, but we will need to keep all CiliumNodes in
			// memory because 'ciliumNodeStore' is used across the operator
			// to get the latest state of a CiliumNode.

			// Since we won't be handling any events we don't need to convert
			// objects.
			ciliumNodeConvertFunc = nil
		} else {
			// nodeManager not nil but the KVStore is nil thus the events
			// will only be relevant to the nodeManager.
			resourceEventHandler = cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						// node is deep copied before it is stored in pkg/aws/eni
						nodeManager.Create(ciliumNode)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					if oldNode := k8s.ObjToCiliumNode(oldObj); oldNode != nil {
						if newNode := k8s.ObjToCiliumNode(newObj); newNode != nil {
							if oldNode.DeepEqual(newNode) {
								return
							}
							// node is deep copied before it is stored in pkg/aws/eni
							nodeManager.Update(newNode)
						} else {
							log.Warningf("Unknown CiliumNode object type %T received: %+v", newNode, newNode)
						}
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
					}
				},
				DeleteFunc: func(obj interface{}) {
					if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
						nodeManager.Delete(ciliumNode.Name)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", obj, obj)
					}
				},
			}
		}
	}

	// TODO: The operator is currently storing a full copy of the
	// CiliumNode resource, as the resource grows, we may want to consider
	// introducing a slim version of it.
	var ciliumNodeInformer cache.Controller
	ciliumNodeStore, ciliumNodeInformer = informer.NewInformer(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			cilium_v2.CNPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNode{},
		0,
		resourceEventHandler,
		ciliumNodeConvertFunc,
	)

	go func() {
		cache.WaitForCacheSync(wait.NeverStop, ciliumNodeInformer.HasSynced)
		close(k8sCiliumNodesCacheSynced)
	}()

	go ciliumNodeInformer.Run(wait.NeverStop)

	return nil
}

type ciliumNodeUpdateImplementation struct{}

func (c *ciliumNodeUpdateImplementation) Create(node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Create(context.TODO(), node, meta_v1.CreateOptions{})
}

func (c *ciliumNodeUpdateImplementation) Get(node string) (*cilium_v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Get(context.TODO(), node, meta_v1.GetOptions{})
}

func (c *ciliumNodeUpdateImplementation) UpdateStatus(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return ciliumK8sClient.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Update(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return ciliumK8sClient.CiliumV2().CiliumNodes().Update(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Delete(nodeName string) error {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Delete(context.TODO(), nodeName, meta_v1.DeleteOptions{})
}

func RunCNPNodeStatusGC(nodeStore cache.Store) {
	go runCNPNodeStatusGC("cnp-node-gc", false, nodeStore)
	go runCNPNodeStatusGC("ccnp-node-gc", true, nodeStore)
}

// runCNPNodeStatusGC runs the node status garbage collector for cilium network
// policies. The policy corresponds to CiliumClusterwideNetworkPolicy if the clusterwide
// parameter is true and CiliumNetworkPolicy otherwise.
func runCNPNodeStatusGC(name string, clusterwide bool, nodeStore cache.Store) {
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
							if _, exists, err := nodeStore.GetByKey(n); !exists && err == nil {
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
