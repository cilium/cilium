// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	ciliumNodeGCControllerGroup = controller.NewGroup("cilium-node-gc")

	ctrlMgr = controller.NewManager()
)

// skipGCAnnotationKey is the key of the annotation to prevent garbage collecting
// the corresponding CiliumNode.
const skipGCAnnotationKey = "cilium.io/do-not-gc"

// ciliumNodeGCCandidate keeps track of cilium nodes, which are candidate for GC.
// Underlying there is a map with node name as key, and last marked timestamp as value.
type ciliumNodeGCCandidate struct {
	lock          lock.RWMutex
	nodesToRemove map[string]time.Time
}

func newCiliumNodeGCCandidate() *ciliumNodeGCCandidate {
	return &ciliumNodeGCCandidate{
		nodesToRemove: map[string]time.Time{},
	}
}

func (c *ciliumNodeGCCandidate) Get(nodeName string) (time.Time, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	val, exists := c.nodesToRemove[nodeName]
	return val, exists
}

func (c *ciliumNodeGCCandidate) Add(nodeName string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.nodesToRemove[nodeName] = time.Now()
}

func (c *ciliumNodeGCCandidate) Delete(nodeName string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.nodesToRemove, nodeName)
}

// RunCiliumNodeGC performs garbage collector for cilium node resource
func RunCiliumNodeGC(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset, ciliumNodes resource.Resource[*cilium_v2.CiliumNode], interval time.Duration, logger *slog.Logger,
	mp workqueue.MetricsProvider) {
	nodesInit(wg, clientset.Slim(), ctx.Done(), mp)

	// wait for k8s nodes synced is done
	select {
	case <-slimNodeStoreSynced:
	case <-ctx.Done():
		return
	}

	ciliumNodeStore, err := ciliumNodes.Store(ctx)
	if err != nil {
		return
	}

	logger.InfoContext(ctx, "Starting to garbage collect stale CiliumNode custom resources")

	candidateStore := newCiliumNodeGCCandidate()
	// create the controller to perform mark and sweep operation for cilium nodes
	ctrlMgr.UpdateController("cilium-node-gc",
		controller.ControllerParams{
			Group:   ciliumNodeGCControllerGroup,
			Context: ctx,
			DoFunc: func(ctx context.Context) error {
				return performCiliumNodeGC(ctx, clientset.CiliumV2().CiliumNodes(), ciliumNodeStore,
					nodeGetter{}, interval, candidateStore, logger)
			},
			RunInterval: interval,
		},
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		ctrlMgr.RemoveControllerAndWait("cilium-node-gc")
	}()
}

func performCiliumNodeGC(ctx context.Context, client ciliumv2.CiliumNodeInterface, ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
	nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate, logger *slog.Logger) error {
	iter := ciliumNodeStore.IterKeys()
	for iter.Next() {
		key := iter.Key()
		nodeName := key.Name

		scopedLog := logger.With(logfields.NodeName, nodeName)
		_, err := nodeGetter.GetK8sSlimNode(nodeName)
		if err == nil {
			scopedLog.DebugContext(ctx, "CiliumNode is valid, no garbage collection required")
			continue
		}

		if !k8serrors.IsNotFound(err) {
			scopedLog.ErrorContext(ctx, "Unable to fetch k8s node from store", logfields.Error, err)
			return err
		}

		cn, _, err := ciliumNodeStore.GetByKey(key)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Unable to fetch CiliumNode from store", logfields.Error, err)
			return err
		}

		// if there is owner references, let k8s handle garbage collection
		if len(cn.GetOwnerReferences()) > 0 {
			continue
		}

		// The user explicitly requested to not GC this CiliumNode object.
		if value, ok := cn.GetAnnotations()[skipGCAnnotationKey]; ok && strings.ToLower(value) == "true" {
			continue
		}

		lastMarkedTime, exists := candidateStore.Get(nodeName)
		if !exists {
			scopedLog.InfoContext(ctx, "Add CiliumNode to garbage collector candidates")
			candidateStore.Add(nodeName)
			continue
		}

		// only remove the node if last marked time is more than running interval
		if lastMarkedTime.Before(time.Now().Add(-interval)) {
			scopedLog.InfoContext(ctx, "Perform GC for invalid CiliumNode")
			err = client.Delete(ctx, nodeName, metav1.DeleteOptions{})
			if err != nil && !k8serrors.IsNotFound(err) {
				scopedLog.ErrorContext(ctx, "Failed to delete invalid CiliumNode", logfields.Error, err)
				return err
			}
			scopedLog.InfoContext(ctx, "CiliumNode is garbage collected successfully")
			candidateStore.Delete(nodeName)
		}
	}
	return nil
}
