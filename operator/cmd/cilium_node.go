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

	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ciliumNodeManagerQueueSyncedKey indicates that the caches
// are synced. The underscore prefix ensures that it can never
// clash with a real key, as Kubernetes does not allow object
// names to start with an underscore.
const ciliumNodeManagerQueueSyncedKey = "_ciliumNodeManagerQueueSynced"

type ciliumNodeSynchronizer struct {
	logger      *slog.Logger
	clientset   k8sClient.Clientset
	nodeManager allocator.NodeEventHandler

	// ciliumNodeStore contains all CiliumNodes present in k8s.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced    chan struct{}
	ciliumNodeManagerQueueSynced chan struct{}
	workqueueMetricsProvider     workqueue.MetricsProvider
}

func newCiliumNodeSynchronizer(logger *slog.Logger, clientset k8sClient.Clientset, nodeManager allocator.NodeEventHandler, workqueueMetricsProvider workqueue.MetricsProvider) *ciliumNodeSynchronizer {
	return &ciliumNodeSynchronizer{
		logger:      logger,
		clientset:   clientset,
		nodeManager: nodeManager,

		k8sCiliumNodesCacheSynced:    make(chan struct{}),
		ciliumNodeManagerQueueSynced: make(chan struct{}),
		workqueueMetricsProvider:     workqueueMetricsProvider,
	}
}

func (s *ciliumNodeSynchronizer) Start(ctx context.Context, wg *sync.WaitGroup) error {
	var (
		nodeManagerSyncHandler func(key string) error
		resourceEventHandler   = cache.ResourceEventHandlerFuncs{}
	)

	var ciliumNodeManagerQueueConfig = workqueue.TypedRateLimitingQueueConfig[string]{
		Name:            "node_manager",
		MetricsProvider: s.workqueueMetricsProvider,
	}

	if operatorOption.Config.EnableMetrics {
		ciliumNodeManagerQueueConfig.MetricsProvider = s.workqueueMetricsProvider
	}

	var ciliumNodeManagerQueue = workqueue.NewTypedRateLimitingQueueWithConfig[string](workqueue.DefaultTypedControllerRateLimiter[string](), ciliumNodeManagerQueueConfig)

	s.logger.InfoContext(ctx, "Starting to synchronize CiliumNode custom resources")

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

	// If both nodeManager and KVStore are nil, then we don't need to handle
	// any watcher events, but we will need to keep all CiliumNodes in
	// memory because 'ciliumNodeStore' is used across the operator
	// to get the latest state of a CiliumNode.
	if s.nodeManager != nil {
		resourceEventHandler = cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					s.logger.WarnContext(ctx, "Unable to process CiliumNode Add event", logfields.Error, err)
					return
				}
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
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
							s.logger.WarnContext(ctx, "Unable to process CiliumNode Update event", logfields.Error, err)
							return
						}
						if s.nodeManager != nil {
							ciliumNodeManagerQueue.Add(key)
						}
					} else {
						s.logger.WarnContext(ctx,
							"Unknown CiliumNode object type received",
							logfields.Type, reflect.TypeOf(newNode),
							logfields.Node, newNode,
						)
					}
				} else {
					s.logger.WarnContext(ctx,
						"Unknown CiliumNode object type received",
						logfields.Type, reflect.TypeOf(oldNode),
						logfields.Node, oldNode,
					)
				}
			},
			DeleteFunc: func(obj any) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					s.logger.WarnContext(ctx, "Unable to process CiliumNode Delete event", logfields.Error, err)
					return
				}
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
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
		s.logger.InfoContext(ctx, "CiliumNodes caches synced with Kubernetes")
		// Only handle events if nodeManagerSyncHandler is not nil. If it is nil
		// then there isn't any event handler set for CiliumNodes events.
		if nodeManagerSyncHandler != nil {
			go func() {
				// infinite loop. run in a goroutine to unblock code execution
				for s.processNextWorkItem(ciliumNodeManagerQueue, nodeManagerSyncHandler) {
				}
			}()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
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
