// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/time/rate"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
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
	cluster string
	name    string
}

func (c *ciliumNodeName) GetKeyName() string {
	return nodeTypes.GetKeyNodeName(c.cluster, c.name)
}

type ciliumNodeManagerQueueSyncedKey struct{}

type ciliumNodeSynchronizer struct {
	clientset   k8sClient.Clientset
	nodeManager allocator.NodeEventHandler
	withKVStore bool

	// ciliumNodeStore contains all CiliumNodes present in k8s.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced    chan struct{}
	ciliumNodeManagerQueueSynced chan struct{}
}

func newCiliumNodeSynchronizer(clientset k8sClient.Clientset, nodeManager allocator.NodeEventHandler, withKVStore bool) *ciliumNodeSynchronizer {
	return &ciliumNodeSynchronizer{
		clientset:   clientset,
		nodeManager: nodeManager,
		withKVStore: withKVStore,

		k8sCiliumNodesCacheSynced:    make(chan struct{}),
		ciliumNodeManagerQueueSynced: make(chan struct{}),
	}
}

func (s *ciliumNodeSynchronizer) Start(ctx context.Context, wg *sync.WaitGroup) error {
	var (
		ciliumNodeKVStore      *store.SharedStore
		err                    error
		nodeManagerSyncHandler func(key string) error
		kvStoreSyncHandler     func(key string) error
		connectedToKVStore     = make(chan struct{})

		resourceEventHandler   = cache.ResourceEventHandlerFuncs{}
		ciliumNodeConvertFunc  = k8s.ConvertToCiliumNode
		ciliumNodeManagerQueue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
		kvStoreQueue           = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	)

	// KVStore is enabled -> we will run the event handler to sync objects into
	// KVStore.
	if s.withKVStore {
		// Connect to the KVStore asynchronously so that we are able to start
		// the operator without relying on the KVStore to be up.
		// Start a goroutine to GC all CiliumNodes from the KVStore that are
		// no longer running.
		wg.Add(1)
		go func() {
			defer wg.Done()

			log.Info("Starting to synchronize CiliumNode custom resources to KVStore")

			ciliumNodeKVStore, err = store.JoinSharedStore(store.Configuration{
				Prefix:     nodeStore.NodeStorePrefix,
				KeyCreator: nodeStore.KeyCreator,
			})

			if err != nil {
				log.WithError(err).Fatal("Unable to setup node watcher")
			}
			close(connectedToKVStore)

			<-s.k8sCiliumNodesCacheSynced
			// Since we processed all events received from k8s we know that
			// at this point the list in ciliumNodeStore should be the source of
			// truth and we need to delete all nodes in the kvNodeStore that are
			// *not* present in the ciliumNodeStore.
			listOfCiliumNodes := s.ciliumNodeStore.ListKeys()

			kvStoreNodes := ciliumNodeKVStore.SharedKeysMap()

			for _, ciliumNode := range listOfCiliumNodes {
				// The remaining kvStoreNodes are leftovers that need to be GCed
				kvStoreNodeName := nodeTypes.GetKeyNodeName(option.Config.ClusterName, ciliumNode)
				delete(kvStoreNodes, kvStoreNodeName)
			}

			if len(listOfCiliumNodes) == 0 && len(kvStoreNodes) != 0 {
				log.Warn("Preventing GC of nodes in the KVStore due the nonexistence of any CiliumNodes in kube-apiserver")
				return
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

	if s.nodeManager != nil {
		nodeManagerSyncHandler = s.syncHandlerConstructor(
			func(node *cilium_v2.CiliumNode) {
				s.nodeManager.Delete(node)
			},
			func(node *cilium_v2.CiliumNode) {
				// node is deep copied before it is stored in pkg/aws/eni
				s.nodeManager.Update(node)
			})
	}

	if s.withKVStore {
		kvStoreSyncHandler = s.syncHandlerConstructor(
			func(node *cilium_v2.CiliumNode) {
				nodeDel := ciliumNodeName{
					cluster: option.Config.ClusterName,
					name:    node.Name,
				}
				ciliumNodeKVStore.DeleteLocalKey(ctx, &nodeDel)
			},
			func(node *cilium_v2.CiliumNode) {
				nodeNew := nodeTypes.ParseCiliumNode(node)
				ciliumNodeKVStore.UpdateKeySync(ctx, &nodeNew, false)
			})
	}

	// If both nodeManager and KVStore are nil, then we don't need to handle
	// any watcher events, but we will need to keep all CiliumNodes in
	// memory because 'ciliumNodeStore' is used across the operator
	// to get the latest state of a CiliumNode.
	if s.withKVStore || s.nodeManager != nil {
		resourceEventHandler = cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					log.WithError(err).Warning("Unable to process CiliumNode Add event")
					return
				}
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
				}
				if s.withKVStore {
					kvStoreQueue.Add(key)
				}
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
						if s.nodeManager != nil {
							ciliumNodeManagerQueue.Add(key)
						}
						if s.withKVStore {
							kvStoreQueue.Add(key)
						}
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
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
				}
				if s.withKVStore {
					kvStoreQueue.Add(key)
				}
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
	s.ciliumNodeStore, ciliumNodeInformer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumNodeList](s.clientset.CiliumV2().CiliumNodes()),
		&cilium_v2.CiliumNode{},
		0,
		resourceEventHandler,
		ciliumNodeConvertFunc,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		cache.WaitForCacheSync(ctx.Done(), ciliumNodeInformer.HasSynced)
		close(s.k8sCiliumNodesCacheSynced)
		ciliumNodeManagerQueue.Add(ciliumNodeManagerQueueSyncedKey{})
		log.Info("CiliumNodes caches synced with Kubernetes")
		// Only handle events if nodeManagerSyncHandler is not nil. If it is nil
		// then there isn't any event handler set for CiliumNodes events.
		if nodeManagerSyncHandler != nil {
			go func() {
				// infinite loop. run in a goroutine to unblock code execution
				for s.processNextWorkItem(ciliumNodeManagerQueue, nodeManagerSyncHandler) {
				}
			}()
		}
		// Start handling events for KVStore **after** nodeManagerSyncHandler
		// otherwise Cilium Operator will block until the KVStore is available.
		// This might be problematic in clusters that have etcd-operator with
		// cluster-pool ipam mode because they depend on Cilium Operator to be
		// running and handling IP Addresses with nodeManagerSyncHandler.
		// Only handle events if kvStoreSyncHandler is not nil. If it is nil
		// then there isn't any event handler set for CiliumNodes events.
		if s.withKVStore && kvStoreSyncHandler != nil {
			<-connectedToKVStore
			log.Info("Connected to the KVStore, syncing CiliumNodes to the KVStore")
			// infinite loop it will block code execution
			for s.processNextWorkItem(kvStoreQueue, kvStoreSyncHandler) {
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer kvStoreQueue.ShutDown()
		defer ciliumNodeManagerQueue.ShutDown()

		ciliumNodeInformer.Run(ctx.Done())
	}()

	return nil
}

func (s *ciliumNodeSynchronizer) syncHandlerConstructor(notFoundHandler func(node *cilium_v2.CiliumNode), foundHandler func(node *cilium_v2.CiliumNode)) func(key string) error {
	return func(key string) error {
		_, name, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			log.WithError(err).Error("Unable to process CiliumNode event")
			return err
		}
		obj, exists, err := s.ciliumNodeStore.GetByKey(name)

		// Delete handling
		if !exists || errors.IsNotFound(err) {
			notFoundHandler(&cilium_v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: name,
				},
			})
			return nil
		}
		if err != nil {
			log.WithError(err).Warning("Unable to retrieve CiliumNode from watcher store")
			return err
		}
		cn, ok := obj.(*cilium_v2.CiliumNode)
		if !ok {
			tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
			if !ok {
				return fmt.Errorf("couldn't get object from tombstone %T", obj)
			}
			cn, ok = tombstone.Obj.(*cilium_v2.CiliumNode)
			if !ok {
				return fmt.Errorf("tombstone contained object that is not a *cilium_v2.CiliumNode %T", obj)
			}
		}
		if cn.DeletionTimestamp != nil {
			notFoundHandler(cn)
			return nil
		}
		foundHandler(cn)
		return nil
	}
}

// processNextWorkItem process all events from the workqueue.
func (s *ciliumNodeSynchronizer) processNextWorkItem(queue workqueue.RateLimitingInterface, syncHandler func(key string) error) bool {
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	if _, ok := key.(ciliumNodeManagerQueueSyncedKey); ok {
		close(s.ciliumNodeManagerQueueSynced)
		return true
	}

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

type ciliumNodeUpdateImplementation struct {
	clientset k8sClient.Clientset
}

func (c *ciliumNodeUpdateImplementation) Create(node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	return c.clientset.CiliumV2().CiliumNodes().Create(context.TODO(), node, meta_v1.CreateOptions{})
}

func (c *ciliumNodeUpdateImplementation) Get(node string) (*cilium_v2.CiliumNode, error) {
	return c.clientset.CiliumV2().CiliumNodes().Get(context.TODO(), node, meta_v1.GetOptions{})
}

func (c *ciliumNodeUpdateImplementation) UpdateStatus(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return c.clientset.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Update(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return c.clientset.CiliumV2().CiliumNodes().Update(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func RunCNPNodeStatusGC(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset, nodeStore cache.Store) {
	runCNPNodeStatusGC("cnp-node-gc", false, ctx, wg, clientset, nodeStore)
	runCNPNodeStatusGC("ccnp-node-gc", true, ctx, wg, clientset, nodeStore)
}

// runCNPNodeStatusGC runs the node status garbage collector for cilium network
// policies. The policy corresponds to CiliumClusterwideNetworkPolicy if the clusterwide
// parameter is true and CiliumNetworkPolicy otherwise.
func runCNPNodeStatusGC(name string, clusterwide bool, ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset, nodeStore cache.Store) {
	parallelRequests := 4
	removeNodeFromCNP := make(chan func(), 50)
	wg.Add(parallelRequests)
	for i := 0; i < parallelRequests; i++ {
		go func() {
			defer wg.Done()
			for f := range removeNodeFromCNP {
				f()
			}
		}()
	}

	mgr := controller.NewManager()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		mgr.RemoveAllAndWait()
	}()

	mgr.UpdateController(name,
		controller.ControllerParams{
			RunInterval: operatorOption.Config.CNPNodeStatusGCInterval,
			StopFunc: func(context.Context) error {
				close(removeNodeFromCNP)
				return nil
			},
			DoFunc: func(ctx context.Context) error {
				lastRun := v1.NewTime(v1.Now().Add(-operatorOption.Config.CNPNodeStatusGCInterval))
				continueID := ""
				wg := sync.WaitGroup{}
				defer wg.Wait()

				for {
					var cnpItemsList []cilium_v2.CiliumNetworkPolicy

					if clusterwide {
						ccnpList, err := clientset.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx,
							meta_v1.ListOptions{
								Limit:    10,
								Continue: continueID,
							})
						if err != nil {
							return err
						}

						cnpItemsList = make([]cilium_v2.CiliumNetworkPolicy, 0, len(ccnpList.Items))
						for _, ccnp := range ccnpList.Items {
							cnpItemsList = append(cnpItemsList, cilium_v2.CiliumNetworkPolicy{
								ObjectMeta: meta_v1.ObjectMeta{
									Name: ccnp.Name,
								},
								Status: ccnp.Status,
							})
						}
						continueID = ccnpList.Continue
					} else {
						cnpList, err := clientset.CiliumV2().CiliumNetworkPolicies(core_v1.NamespaceAll).List(ctx,
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
								// To avoid concurrency issues where a node is
								// created and adds its CNP Status before the operator
								// node watcher receives an event that the node
								// was created, we will only delete the node
								// from the CNP Status if the last time it was
								// updated was before the lastRun.
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
								updateCNP(ctx, clientset.CiliumV2(), cnpCpy, nodesToDelete)
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
			Context: ctx,
		})
}

func updateCNP(ctx context.Context, ciliumClient v2.CiliumV2Interface, cnp *cilium_v2.CiliumNetworkPolicy, nodesToDelete map[string]v1.Time) {
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
			_, err = ciliumClient.CiliumClusterwideNetworkPolicies().Patch(ctx,
				cnp.GetName(), types.JSONPatchType, removeStatusNodeJSON, meta_v1.PatchOptions{}, "status")
		} else {
			_, err = ciliumClient.CiliumNetworkPolicies(ns).Patch(ctx,
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

func RunCNPStatusNodesCleaner(ctx context.Context, clientset k8sClient.Clientset, rateLimit *rate.Limiter) {
	go clearCNPStatusNodes(ctx, false, clientset, rateLimit)
	go clearCNPStatusNodes(ctx, true, clientset, rateLimit)
}

func clearCNPStatusNodes(ctx context.Context, clusterwide bool, clientset k8sClient.Clientset, rateLimit *rate.Limiter) {
	body, err := json.Marshal([]k8s.JSONPatch{
		{
			OP:   "remove",
			Path: "/status/nodes",
		},
	})
	if err != nil {
		log.WithError(err).Debug("Unable to json marshal")
		return
	}

	continueID := ""
	nCNPs, nGcCNPs := 0, 0
	for {
		if clusterwide {
			if err := rateLimit.Wait(ctx); err != nil {
				log.WithError(err).Debug("Error while rate limiting CCNP List requests")
				return
			}

			ccnpList, err := clientset.CiliumV2().CiliumClusterwideNetworkPolicies().List(
				ctx,
				meta_v1.ListOptions{
					Limit:    10,
					Continue: continueID,
				})
			if err != nil {
				log.WithError(err).Debug("Unable to list CCNPs")
				return
			}
			nCNPs += len(ccnpList.Items)
			continueID = ccnpList.Continue

			for _, cnp := range ccnpList.Items {
				if len(cnp.Status.Nodes) == 0 {
					continue
				}

				if err := rateLimit.Wait(ctx); err != nil {
					log.WithError(err).Debug("Error while rate limiting CCNP PATCH requests")
					return
				}

				_, err = clientset.CiliumV2().CiliumClusterwideNetworkPolicies().Patch(ctx,
					cnp.Name, types.JSONPatchType, body, meta_v1.PatchOptions{}, "status")

				if err != nil {
					if errors.IsInvalid(err) {
						// An "Invalid" error may be returned if /status/nodes path does not exist.
						// In that case, we simply ignore it, since there are no updates to clean up.
						continue
					}
					log.WithError(err).Debug("Unable to PATCH while clearing status nodes in CCNP")
				}
				nGcCNPs++
			}
		} else {
			if err := rateLimit.Wait(ctx); err != nil {
				log.WithError(err).Debug("Error while rate limiting CNP List requests")
				return
			}

			cnpList, err := clientset.CiliumV2().CiliumNetworkPolicies(core_v1.NamespaceAll).List(
				ctx,
				meta_v1.ListOptions{
					Limit:    10,
					Continue: continueID,
				})
			if err != nil {
				log.WithError(err).Debug("Unable to list CNPs")
				return
			}
			nCNPs += len(cnpList.Items)
			continueID = cnpList.Continue

			for _, cnp := range cnpList.Items {
				if len(cnp.Status.Nodes) == 0 {
					continue
				}

				namespace := utils.ExtractNamespace(&cnp.ObjectMeta)

				if err := rateLimit.Wait(ctx); err != nil {
					log.WithError(err).Debug("Error while rate limiting CNP PATCH requests")
					return
				}

				_, err = clientset.CiliumV2().CiliumNetworkPolicies(namespace).Patch(ctx,
					cnp.Name, types.JSONPatchType, body, meta_v1.PatchOptions{}, "status")
				if err != nil {
					if errors.IsInvalid(err) {
						// An "Invalid" error may be returned if /status/nodes path does not exist.
						// In that case, we simply ignore it, since there are no updates to clean up.
						continue
					}
					log.WithError(err).Debug("Unable to PATCH while clearing status nodes in CNP")
				}
				nGcCNPs++
			}
		}

		if continueID == "" {
			break
		}
	}

	if clusterwide {
		log.Infof("Garbage collected status/nodes in Cilium Clusterwide Network Policies found=%d, gc=%d", nCNPs, nGcCNPs)
	} else {
		log.Infof("Garbage collected status/nodes in Cilium Network Policies found=%d, gc=%d", nCNPs, nGcCNPs)
	}
}
