// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

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
func RunCiliumNodeGC(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset, ciliumNodeStore cache.Store, interval time.Duration) {
	nodesInit(wg, clientset.Slim(), ctx.Done())

	// wait for k8s nodes synced is done
	select {
	case <-slimNodeStoreSynced:
	case <-ctx.Done():
		return
	}

	log.Info("Starting to garbage collect stale CiliumNode custom resources")

	candidateStore := newCiliumNodeGCCandidate()
	// create the controller to perform mark and sweep operation for cilium nodes
	ctrlMgr.UpdateController("cilium-node-gc",
		controller.ControllerParams{
			Context: ctx,
			DoFunc: func(ctx context.Context) error {
				return performCiliumNodeGC(ctx, clientset.CiliumV2().CiliumNodes(), ciliumNodeStore,
					nodeGetter{}, interval, candidateStore)
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

func performCiliumNodeGC(ctx context.Context, client ciliumv2.CiliumNodeInterface, ciliumNodeStore cache.Store,
	nodeGetter slimNodeGetter, interval time.Duration, candidateStore *ciliumNodeGCCandidate) error {
	for _, nodeName := range ciliumNodeStore.ListKeys() {
		scopedLog := log.WithField(logfields.NodeName, nodeName)
		_, err := nodeGetter.GetK8sSlimNode(nodeName)
		if err == nil {
			scopedLog.Debugf("CiliumNode is valid, no gargage collection required")
			continue
		}

		if !k8serrors.IsNotFound(err) {
			scopedLog.WithError(err).Error("Unable to fetch k8s node from store")
			return err
		}

		obj, _, err := ciliumNodeStore.GetByKey(nodeName)
		if err != nil {
			scopedLog.WithError(err).Error("Unable to fetch CiliumNode from store")
			return err
		}

		cn, ok := obj.(*cilium_v2.CiliumNode)
		if !ok {
			scopedLog.Errorf("Object stored in store is not *cilium_v2.CiliumNode but %T", obj)
			return err
		}

		// if there is owner references, let k8s handle garbage collection
		if len(cn.GetOwnerReferences()) > 0 {
			continue
		}

		lastMarkedTime, exists := candidateStore.Get(nodeName)
		if !exists {
			scopedLog.Info("Add CiliumNode to garbage collector candidates")
			candidateStore.Add(nodeName)
			continue
		}

		// only remove the node if last marked time is more than running interval
		if lastMarkedTime.Before(time.Now().Add(-interval)) {
			scopedLog.Info("Perform GC for invalid CiliumNode")
			err = client.Delete(ctx, nodeName, metav1.DeleteOptions{})
			if err != nil && !k8serrors.IsNotFound(err) {
				scopedLog.WithError(err).Error("Failed to delete invalid CiliumNode")
				return err
			}
			scopedLog.Info("CiliumNode is garbage collected successfully")
			candidateStore.Delete(nodeName)
		}
	}
	return nil
}
