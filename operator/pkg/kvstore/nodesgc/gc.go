// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodesgc

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/client-go/util/workqueue"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	// wqRateLimiter is the rate limiter used for the working queue. It can be overridden for testing purposes.
	wqRateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[nodeName](1*time.Second, 120*time.Second)

	// kvstoreUpsertQueueDelay is the delay before checking whether a newly observed kvstore entry should be
	// deleted or not. It is meant to give time to the corresponding CiliumNode to be created as well before
	// attempting deletion, as an additional safety measure in addition to checking whether a Cilium agent is
	// running on that node. It can be overridden for testing purposes.
	kvstoreUpsertQueueDelay = 1 * time.Minute
)

type nodeName string

type gc struct {
	logger *slog.Logger
	jg     job.Group
	cinfo  cmtypes.ClusterInfo

	client       kvstore.Client
	ciliumNodes  resource.Resource[*cilium_api_v2.CiliumNode]
	pods         resource.Resource[*slim_corev1.Pod]
	podsSelector labels.Selector

	queue workqueue.TypedRateLimitingInterface[nodeName]
}

func newGC(in struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Config      Config
	ClusterInfo cmtypes.ClusterInfo

	WQMetricsProvider workqueue.MetricsProvider

	Clientset     k8sClient.Clientset
	KVStoreClient kvstore.Client
	StoreFactory  store.Factory

	CiliumNodes resource.Resource[*cilium_api_v2.CiliumNode]
	Pods        resource.Resource[*slim_corev1.Pod]
}) (*gc, error) {
	if !in.Clientset.IsEnabled() || !in.KVStoreClient.IsEnabled() || !in.Config.Enable {
		return nil, nil
	}

	selector, err := labels.Parse(operatorOption.Config.CiliumPodLabels)
	if err != nil {
		return nil, fmt.Errorf("unable to parse cilium pod selector: %w", err)
	}

	g := gc{
		logger: in.Logger,
		jg:     in.JobGroup,
		cinfo:  in.ClusterInfo,

		client:       in.KVStoreClient,
		ciliumNodes:  in.CiliumNodes,
		pods:         in.Pods,
		podsSelector: selector,

		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			wqRateLimiter,
			workqueue.TypedRateLimitingQueueConfig[nodeName]{
				Name:            "kvstore-nodes",
				MetricsProvider: in.WQMetricsProvider,
			},
		),
	}

	in.JobGroup.Add(
		job.OneShot("gc", g.run),
		job.OneShot("watch-k8s", func(ctx context.Context, health cell.Health) error {
			health.OK("Primed")

			for ev := range g.ciliumNodes.Events(ctx) {
				switch ev.Kind {
				case resource.Delete:
					// Enqueue deleted CiliumNodes, to GC the corresponding kvstore
					// entry if still present.
					g.queue.Add(nodeName(ev.Key.Name))
				case resource.Sync:
					health.OK("Synced")
				}

				ev.Done(nil)
			}

			// We are terminating, shutdown the queue as well
			health.OK("Shutting down")
			g.queue.ShutDownWithDrain()
			return nil
		}),
		job.OneShot("watch-kvstore", func(ctx context.Context, health cell.Health) error {
			health.OK("Primed")
			in.StoreFactory.NewWatchStore(g.cinfo.Name, nodeStore.KeyCreator, &observer{g.queue},
				store.RWSWithOnSyncCallback(func(context.Context) { health.OK("Synced") }),
			).Watch(ctx, g.client, path.Join(nodeStore.NodeStorePrefix, g.cinfo.Name))
			return nil
		}),
	)

	return &g, nil
}

func (g *gc) run(ctx context.Context, health cell.Health) error {
	health.OK("Initializing")

	ciliumNodes, err := g.ciliumNodes.Store(ctx)
	if err != nil {
		return fmt.Errorf("retrieving CiliumNodes store: %w", err)
	}

	pods, err := g.pods.Store(ctx)
	if err != nil {
		return fmt.Errorf("retrieving Pods store: %w", err)
	}

	health.OK("Initialized")
	for g.processNextWorkItem(func(nodeName nodeName) error {
		// Check if the CiliumNode still exists, or got recreated, as we don't
		// need to do anything in that case.
		if _, exists, err := ciliumNodes.GetByKey(resource.Key{Name: string(nodeName)}); err != nil {
			return fmt.Errorf("retrieving CiliumNode %q: %w", nodeName, err)
		} else if exists {
			return nil
		}

		// Check if a Cilium agent is still running on the given node, and
		// in that case retry later, because it would recognize the deletion
		// event and recreate the kvstore entry right away. Hence, defeating
		// the whole purpose of this GC logic, and leading to the node entry
		// being eventually deleted by the lease expiration only.
		found, err := pods.ByIndex(operatorK8s.PodNodeNameIndex, string(nodeName))
		if err != nil {
			return fmt.Errorf("retrieving pods indexed by node %q: %w", nodeName, err)
		}

		for _, pod := range found {
			if utils.IsPodRunning(pod.Status) && g.podsSelector.Matches(labels.Set(pod.Labels)) {
				return fmt.Errorf("delaying deletion from kvstore, as Cilium agent is still running on %q", nodeName)
			}
		}

		key := path.Join(nodeStore.NodeStorePrefix, nodeTypes.GetKeyNodeName(g.cinfo.Name, string(nodeName)))
		if err := g.client.Delete(ctx, key); err != nil {
			return fmt.Errorf("deleting node from kvstore: %w", err)
		}

		g.logger.Info("Successfully deleted stale node entry from kvstore", logfields.NodeName, nodeName)
		health.OK("Stale node entry GCed")
		return nil
	}) {
	}

	return nil
}

func (g *gc) processNextWorkItem(handler func(nodeName nodeName) error) bool {
	nodeName, quit := g.queue.Get()
	if quit {
		return false
	}

	defer g.queue.Done(nodeName)

	err := handler(nodeName)
	if err == nil {
		if g.queue.NumRequeues(nodeName) > 0 {
			g.logger.Info("Successfully reconciled node after retries", logfields.NodeName, nodeName)
		}
		g.queue.Forget(nodeName)
		return true
	}

	const silentRetries = 5
	log := g.logger.Info
	if g.queue.NumRequeues(nodeName) >= silentRetries {
		log = g.logger.Warn
	}

	log("Failed reconciling node, will retry",
		logfields.Error, err,
		logfields.NodeName, nodeName,
	)

	g.queue.AddRateLimited(nodeName)
	return true
}

type observer struct {
	queue workqueue.TypedRateLimitingInterface[nodeName]
}

func (o *observer) OnUpdate(key store.Key) {
	// Add the entry after a delay, as an extra safety measure, in addition to
	// checking whether there's no Cilium pod running on that node, to prevent
	// deleting newly created entries due to race conditions.
	o.queue.AddAfter(nodeName(key.(*nodeTypes.Node).Name), kvstoreUpsertQueueDelay)
}

func (o *observer) OnDelete(store.NamedKey) {}
