// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
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
	"github.com/cilium/cilium/pkg/option"
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
	var candidateStore *ciliumNodeGCCandidate
	var ciliumNodeStore resource.Store[*cilium_v2.CiliumNode]
	var err error
	var shouldGC func(ctx context.Context, nodeName string, ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
		nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate, scopedLog *slog.Logger) (bool, error)

	if !option.Config.EnableCiliumNodeCRD {
		logger.InfoContext(ctx, "Running one-off GC of CiliumNode CRD when disabled")
		interval = 0
		shouldGC = shouldGCNodeCRDDisabled
	} else {
		nodesInit(wg, clientset.Slim(), ctx.Done(), mp)

		// wait for k8s nodes synced is done
		select {
		case <-slimNodeStoreSynced:
		case <-ctx.Done():
			return
		}

		logger.InfoContext(ctx, "Starting to garbage collect stale CiliumNode custom resources")
		candidateStore = newCiliumNodeGCCandidate()
		shouldGC = shouldGCNode
	}

	ciliumNodeStore, err = ciliumNodes.Store(ctx)
	if err != nil {
		return
	}

	// create the controller to perform mark and sweep operation for cilium nodes
	ctrlMgr.UpdateController("cilium-node-gc",
		controller.ControllerParams{
			Group:   ciliumNodeGCControllerGroup,
			Context: ctx,
			DoFunc: func(ctx context.Context) error {
				return performCiliumNodeGC(ctx, clientset.CiliumV2().CiliumNodes(), ciliumNodeStore,
					nodeGetter{}, interval, candidateStore, logger, shouldGC)
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

// Runs the garbage collection for CiliumNode resources, for both CiliumNode CRD enabled and disabled modes.
func performCiliumNodeGC(ctx context.Context, client ciliumv2.CiliumNodeInterface, ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
	nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate, logger *slog.Logger,
	shouldGCNodePred func(ctx context.Context, nodeName string, ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
		nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate, scopedLog *slog.Logger) (bool, error)) error {
	var retErr error
	iter := ciliumNodeStore.IterKeys()
	for iter.Next() {
		key := iter.Key()
		nodeName := key.Name
		scopedLog := logger.With(logfields.NodeName, nodeName)

		shouldGC, err := shouldGCNodePred(ctx, nodeName, ciliumNodeStore, nodeGetter, interval, candidateStore, scopedLog)
		if err != nil {
			retErr = errors.Join(retErr, err)
			continue
		}
		if !shouldGC {
			continue
		}

		scopedLog.InfoContext(ctx, "Perform GC for invalid CiliumNode")
		err = client.Delete(ctx, nodeName, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			scopedLog.ErrorContext(ctx, "Failed to delete invalid CiliumNode", logfields.Error, err)
			retErr = errors.Join(retErr, err)
			continue
		}
		scopedLog.InfoContext(ctx, "CiliumNode is garbage collected successfully")
		if candidateStore != nil {
			candidateStore.Delete(nodeName)
		}
	}
	return retErr
}

// Returns whether the CiliumNode with the given name should be garbage collected. Predicate function for default CiliumNode GC.
func shouldGCNode(ctx context.Context, nodeName string, ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
	nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate, scopedLog *slog.Logger) (bool, error) {
	_, err := nodeGetter.GetK8sSlimNode(nodeName)
	if err == nil {
		scopedLog.DebugContext(ctx, "CiliumNode is valid, no garbage collection required")
		return false, nil
	}

	if !k8serrors.IsNotFound(err) {
		scopedLog.ErrorContext(ctx, "Unable to fetch k8s node from store", logfields.Error, err)
		return false, err
	}

	cn, _, err := ciliumNodeStore.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to fetch CiliumNode from store", logfields.Error, err)
		return false, err
	}

	// if there is owner references, let k8s handle garbage collection
	if len(cn.GetOwnerReferences()) > 0 {
		return false, nil
	}

	// The user explicitly requested to not GC this CiliumNode object.
	if value, ok := cn.GetAnnotations()[skipGCAnnotationKey]; ok && strings.ToLower(value) == "true" {
		return false, nil
	}

	lastMarkedTime, exists := candidateStore.Get(nodeName)
	if !exists {
		scopedLog.InfoContext(ctx, "Add CiliumNode to garbage collector candidates")
		candidateStore.Add(nodeName)
		return false, nil
	}

	// only remove the node if last marked time is more than running interval
	if lastMarkedTime.Before(time.Now().Add(-interval)) {
		return true, nil
	}

	return false, nil
}

// Returns whether the CiliumNode with the given name should be garbage collected. Predicate function for one-off GC when CiliumNode CRD is disabled.
func shouldGCNodeCRDDisabled(ctx context.Context, nodeName string, ciliumNodeStore resource.Store[*cilium_v2.CiliumNode],
	nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate, scopedLog *slog.Logger) (bool, error) {
	return true, nil
}
