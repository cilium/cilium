// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/resource"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

// ciliumNodeManagerQueueSyncedKey indicates that the caches
// are synced. The underscore prefix ensures that it can never
// clash with a real key, as Kubernetes does not allow object
// names to start with an underscore.
const ciliumNodeManagerQueueSyncedKey = "_ciliumNodeManagerQueueSynced"

type ciliumNodeSynchronizer struct {
	logger      *slog.Logger
	clientset   k8sClient.Clientset
	nodeManager allocator.NodeEventHandler
	withKVStore bool

	// ciliumNodeStore contains all CiliumNodes present in k8s.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced    chan struct{}
	ciliumNodeManagerQueueSynced chan struct{}
}

func newCiliumNodeSynchronizer(logger *slog.Logger, clientset k8sClient.Clientset, nodeManager allocator.NodeEventHandler, withKVStore bool) *ciliumNodeSynchronizer {
	return &ciliumNodeSynchronizer{
		logger:      logger,
		clientset:   clientset,
		nodeManager: nodeManager,
		withKVStore: withKVStore,

		k8sCiliumNodesCacheSynced:    make(chan struct{}),
		ciliumNodeManagerQueueSynced: make(chan struct{}),
	}
}

func (s *ciliumNodeSynchronizer) Start(ctx context.Context, wg *sync.WaitGroup, podsStore resource.Store[*corev1.Pod]) error {
	var (
		ciliumNodeKVStore      *store.SharedStore
		err                    error
		nodeManagerSyncHandler func(key string) error
		kvStoreSyncHandler     func(key string) error
		connectedToKVStore     = make(chan struct{})
		resourceEventHandler   = cache.ResourceEventHandlerFuncs{}
	)

	var ciliumNodeManagerQueueConfig = workqueue.TypedRateLimitingQueueConfig[string]{
		Name: "node_manager",
	}
	var kvStoreQueueConfig = workqueue.TypedRateLimitingQueueConfig[string]{
		Name: "kvstore",
	}

	if operatorOption.Config.EnableMetrics {
		ciliumNodeManagerQueueConfig.MetricsProvider = NewWorkqueuePrometheusMetricsProvider()
		kvStoreQueueConfig.MetricsProvider = NewWorkqueuePrometheusMetricsProvider()
	}

	var ciliumNodeManagerQueue = workqueue.NewTypedRateLimitingQueueWithConfig[string](workqueue.DefaultTypedControllerRateLimiter[string](), ciliumNodeManagerQueueConfig)
	var kvStoreQueue = workqueue.NewTypedRateLimitingQueueWithConfig[string](
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](1*time.Second, 120*time.Second),
		kvStoreQueueConfig,
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

			s.logger.Info("Starting to synchronize CiliumNode custom resources to KVStore")

			ciliumNodeKVStore, err = store.JoinSharedStore(s.logger,
				store.Configuration{
					Backend:    kvstore.Client(),
					Prefix:     nodeStore.NodeStorePrefix,
					KeyCreator: nodeStore.KeyCreator,
				})

			if err != nil {
				logging.Fatal(s.logger, "Unable to setup node watcher", logfields.Error, err)
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
				s.logger.Warn("Preventing GC of nodes in the KVStore due the nonexistence of any CiliumNodes in kube-apiserver")
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
		s.logger.Info("Starting to synchronize CiliumNode custom resources")
	}

	if s.nodeManager != nil {
		nodeManagerSyncHandler = s.syncHandlerConstructor(
			func(node *cilium_v2.CiliumNode) error {
				s.nodeManager.Delete(node)
				return nil
			},
			func(node *cilium_v2.CiliumNode) error {
				value, ok := node.Annotations[annotation.IPAMIgnore]
				if ok && strings.ToLower(value) == "true" {
					return nil
				}

				// node is deep copied before it is stored in pkg/aws/eni
				s.nodeManager.Upsert(node)
				return nil
			})
	}

	if s.withKVStore {
		ciliumPodsSelector, err := labels.Parse(operatorOption.Config.CiliumPodLabels)
		if err != nil {
			return fmt.Errorf("unable to parse cilium pod selector: %w", err)
		}

		kvStoreSyncHandler = s.syncHandlerConstructor(
			func(node *cilium_v2.CiliumNode) error {
				// Check if a Cilium agent is still running on the given node, and
				// in that case retry later, because it would recognize the deletion
				// event and recreate the kvstore entry right away. Hence, defeating
				// the whole purpose of this GC logic, and leading to the node entry
				// being eventually deleted by the lease expiration only.
				pods, err := podsStore.ByIndex(operatorK8s.PodNodeNameIndex, node.GetName())
				if err != nil {
					return fmt.Errorf("retrieving pods indexed by node %q: %w", node.GetName(), err)
				}

				for _, pod := range pods {
					if utils.IsPodRunning(pod.Status) && ciliumPodsSelector.Matches(labels.Set(pod.Labels)) {
						return fmt.Errorf("skipping deletion from kvstore, as Cilium agent is still running on %q", node.GetName())
					}
				}

				nodeDel := ciliumNodeName{
					cluster: option.Config.ClusterName,
					name:    node.Name,
				}
				ciliumNodeKVStore.DeleteLocalKey(ctx, &nodeDel)
				return nil
			},
			func(node *cilium_v2.CiliumNode) error {
				return nil
			})
	}

	// If both nodeManager and KVStore are nil, then we don't need to handle
	// any watcher events, but we will need to keep all CiliumNodes in
	// memory because 'ciliumNodeStore' is used across the operator
	// to get the latest state of a CiliumNode.
	if s.withKVStore || s.nodeManager != nil {
		resourceEventHandler = cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					s.logger.Warn("Unable to process CiliumNode Add event", logfields.Error, err)
					return
				}
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
				}
				if s.withKVStore {
					kvStoreQueue.Add(key)
				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				if oldNode := informer.CastInformerEvent[cilium_v2.CiliumNode](s.logger, oldObj); oldNode != nil {
					if newNode := informer.CastInformerEvent[cilium_v2.CiliumNode](s.logger, newObj); newNode != nil {
						if oldNode.DeepEqual(newNode) {
							return
						}
						key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
						if err != nil {
							s.logger.Warn("Unable to process CiliumNode Update event", logfields.Error, err)
							return
						}
						if s.nodeManager != nil {
							ciliumNodeManagerQueue.Add(key)
						}
						if s.withKVStore {
							kvStoreQueue.Add(key)
						}
					} else {
						s.logger.Warn(
							"Unknown CiliumNode object type received",
							logfields.Type, reflect.TypeOf(newNode),
							logfields.Node, newNode,
						)
					}
				} else {
					s.logger.Warn(
						"Unknown CiliumNode object type received",
						logfields.Type, reflect.TypeOf(oldNode),
						logfields.Node, oldNode,
					)
				}
			},
			DeleteFunc: func(obj any) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					s.logger.Warn("Unable to process CiliumNode Delete event", logfields.Error, err)
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
		nil,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		cache.WaitForCacheSync(ctx.Done(), ciliumNodeInformer.HasSynced)
		close(s.k8sCiliumNodesCacheSynced)
		ciliumNodeManagerQueue.Add(ciliumNodeManagerQueueSyncedKey)
		s.logger.Info("CiliumNodes caches synced with Kubernetes")
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
		// Only handle events if kvStoreSyncHandler is not nil. If it is nil
		// then there isn't any event handler set for CiliumNodes events.
		if s.withKVStore && kvStoreSyncHandler != nil {
			<-connectedToKVStore
			s.logger.Info("Connected to the KVStore, syncing CiliumNodes to the KVStore")
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

func (s *ciliumNodeSynchronizer) syncHandlerConstructor(notFoundHandler, foundHandler func(node *cilium_v2.CiliumNode) error) func(key string) error {
	return func(key string) error {
		_, name, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			s.logger.Error("Unable to process CiliumNode event", logfields.Error, err)
			return err
		}
		obj, exists, err := s.ciliumNodeStore.GetByKey(name)

		// Delete handling
		if !exists || errors.IsNotFound(err) {
			return notFoundHandler(&cilium_v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: name,
				},
			})
		}
		if err != nil {
			s.logger.Warn("Unable to retrieve CiliumNode from watcher store", logfields.Error, err)
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
			return notFoundHandler(cn)
		}
		return foundHandler(cn)
	}
}

// processNextWorkItem process all events from the workqueue.
func (s *ciliumNodeSynchronizer) processNextWorkItem(queue workqueue.TypedRateLimitingInterface[string], syncHandler func(key string) error) bool {
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	if key == ciliumNodeManagerQueueSyncedKey {
		close(s.ciliumNodeManagerQueueSynced)
		return true
	}

	err := syncHandler(key)
	if err == nil {
		// If err is nil we can forget it from the queue, if it is not nil
		// the queue handler will retry to process this key until it succeeds.
		if queue.NumRequeues(key) > 0 {
			s.logger.Info("CiliumNode successfully reconciled after retries", logfields.NodeName, key)
		}
		queue.Forget(key)
		return true
	}

	const silentRetries = 5
	if queue.NumRequeues(key) < silentRetries {
		s.logger.Info("Failed reconciling CiliumNode, will retry",
			logfields.Error, err,
			logfields.NodeName, key,
		)
	} else {
		s.logger.Warn(
			"Failed reconciling CiliumNode, will retry",
			logfields.Error, err,
			logfields.NodeName, key,
		)
	}

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
