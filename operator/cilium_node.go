// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

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
)

// ciliumNodeName is only used to implement NamedKey interface.
type ciliumNodeName struct {
	name string
}

func (c *ciliumNodeName) GetKeyName() string {
	return c.name
}

var (
	// ciliumNodeStore contains all CiliumNodes present in k8s.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced = make(chan struct{})
)

func startSynchronizingCiliumNodes(ctx context.Context, nodeManager allocator.NodeEventHandler, withKVStore bool) error {
	var (
		ciliumNodeKVStore *store.SharedStore
		err               error
		syncHandler       func(key string) error

		resourceEventHandler  = cache.ResourceEventHandlerFuncs{}
		ciliumNodeConvertFunc = k8s.ConvertToCiliumNode
		queue                 = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	)

	// KVStore is enabled -> we will run the event handler to sync objects into
	// KVStore.
	if withKVStore {
		log.Info("Starting to synchronize CiliumNode custom resources to KVStore")

		ciliumNodeKVStore, err = store.JoinSharedStore(store.Configuration{
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
					ciliumNodeKVStore.DeleteLocalKey(ctx, kvStoreNode)
				}
			}
		}()
	} else {
		log.Info("Starting to synchronize CiliumNode custom resources")
	}

	// If Both nodeManager and KVStore are nil. We don't need to handle
	// any watcher events, but we will need to keep all CiliumNodes in
	// memory because 'ciliumNodeStore' is used across the operator
	// to get the latest state of a CiliumNode.
	if withKVStore || nodeManager != nil {
		syncHandler = func(key string) error {
			_, name, err := cache.SplitMetaNamespaceKey(key)
			if err != nil {
				log.WithError(err).Error("Unable to process CiliumNode event")
				return err
			}
			obj, exists, err := ciliumNodeStore.GetByKey(name)

			// Delete handling
			if !exists || errors.IsNotFound(err) {
				if withKVStore {
					ciliumNodeKVStore.DeleteLocalKey(ctx, &ciliumNodeName{name: name})
				}
				if nodeManager != nil {
					nodeManager.Delete(name)
				}
				return nil
			}
			if err != nil {
				log.WithError(err).Warning("Unable to retrieve CiliumNode from watcher store")
				return err
			}
			cn, ok := obj.(*cilium_v2.CiliumNode)
			if !ok {
				log.Errorf("Object stored in store is not *cilium_v2.CiliumNode but %T", obj)
				return err
			}
			if withKVStore {
				nodeNew := nodeTypes.ParseCiliumNode(cn)
				ciliumNodeKVStore.UpdateKeySync(ctx, &nodeNew)
			}
			if nodeManager != nil {
				// node is deep copied before it is stored in pkg/aws/eni
				nodeManager.Update(cn)
			}
			return nil
		}

		resourceEventHandler = cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					log.WithError(err).Warning("Unable to process CiliumNode Add event")
					return
				}
				queue.Add(key)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldNode := k8s.ObjToCiliumNode(oldObj); oldNode != nil {
					if newNode := k8s.ObjToCiliumNode(newObj); newNode != nil {
						if oldNode.DeepEqual(newNode) {
							return
						}
						key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
						if err != nil {
							log.WithError(err).Warning("Unable to process CiliumNode Update event")
							return
						}
						queue.Add(key)
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", newNode, newNode)
					}
				} else {
					log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
				}
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					log.WithError(err).Warning("Unable to process CiliumNode Delete event")
					return
				}
				queue.Add(key)
			},
		}
	} else {
		// Since we won't be handling any events we don't need to convert
		// objects.
		ciliumNodeConvertFunc = nil
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
		// Only handle events if syncHandler is not nil. If it is nil then
		// there isn't any event handler set for CiliumNodes events.
		if syncHandler != nil {
			for processNextWorkItem(queue, syncHandler) {
			}
		}
	}()

	go ciliumNodeInformer.Run(wait.NeverStop)

	return nil
}

// processNextWorkItem process all events from the workqueue.
func processNextWorkItem(queue workqueue.RateLimitingInterface, syncHandler func(key string) error) bool {
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	err := syncHandler(key.(string))
	if err == nil {
		// If err is nil we can forget it from the queue, if it is not nil
		// the queue handler will retry to process this key until it succeeds.
		queue.Forget(key)
		return true
	}

	log.WithError(err).Errorf("sync %q failed with %v", key, err)
	queue.AddRateLimited(key)

	return true
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
				lastRun := v1.NewTime(v1.Now().Add(-operatorOption.Config.CNPNodeStatusGCInterval))
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
