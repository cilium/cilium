// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

package main

import (
	"context"
	"strings"

	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
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
			v2.CNPluralName, v1.NamespaceAll, fields.Everything()),
		&v2.CiliumNode{},
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

func (c *ciliumNodeUpdateImplementation) Create(node *v2.CiliumNode) (*v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Create(context.TODO(), node, metav1.CreateOptions{})
}

func (c *ciliumNodeUpdateImplementation) Get(node string) (*v2.CiliumNode, error) {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Get(context.TODO(), node, metav1.GetOptions{})
}

func (c *ciliumNodeUpdateImplementation) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return ciliumK8sClient.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, metav1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return ciliumK8sClient.CiliumV2().CiliumNodes().Update(context.TODO(), node, metav1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Delete(nodeName string) error {
	return ciliumK8sClient.CiliumV2().CiliumNodes().Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
}
