// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"

	"k8s.io/client-go/util/workqueue"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}

func (c *Controller) processCiliumIdentityEvents(ctx context.Context) error {
	for event := range c.ciliumIdentity.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert CID event",
				logfields.CIDName, event.Key.String())
			c.onCiliumIdentityUpsertEvent(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete CID event",
				logfields.CIDName, event.Key.String())
			c.onCiliumIdentityDeleteEvent(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) onCiliumIdentityUpsertEvent(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name), 0)
}

func (c *Controller) onCiliumIdentityDeleteEvent(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name), 0)
}

func (c *Controller) initCIDQueue() {
	c.logger.Info("CID controller work queue configuration for CID",
		logfields.WorkQueueSyncBackOff, defaultSyncBackOff)

	c.cidQueue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		workqueue.RateLimitingQueueConfig{Name: "cid"})
}

// runCIDWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// work queue guarantees that they will not end up processing the same CID
// at the same time
func (c *Controller) runCIDWorker(_ context.Context) error {
	c.logger.Info("Starting CID worker in CID controller")
	defer c.logger.Info("Stopping CID worker in CID controller")

	for c.processNextCIDQueueItem() {
		select {
		case <-c.context.Done():
			return nil
		default:
		}
	}

	return nil
}

func (c *Controller) processNextCIDQueueItem() bool {
	item, quit := c.cidQueue.Get()
	if quit {
		return false
	}
	defer c.cidQueue.Done(item)

	cidKey := item.(resource.Key)
	err := c.reconciler.reconcileCID(cidKey)
	c.handleCIDErr(err, item)

	return true
}

func (c *Controller) handleCIDErr(err error, item interface{}) {
	if err == nil {
		c.cidQueue.Forget(item)
		return
	}
	c.logger.Error("Failed to process CID", logfields.CIDName, item, logfields.Error, err)

	if c.cidQueue.NumRequeues(item) < maxProcessRetries {
		c.cidQueue.AddRateLimited(item)
		return
	}

	// Drop the CID from queue, exceeded max retries
	c.logger.Error("Dropping the CID from queue, exceeded maxRetries",
		logfields.CIDName, item,
		logfields.Error, err)

	c.cidQueue.Forget(item)
}

func (c *Controller) enqueueCIDReconciliation(cidKey resource.Key, delay time.Duration) {
	if len(cidKey.String()) == 0 {
		return
	}

	c.cidEnqueuedAt.SetEnqueueTimeIfNotSet(cidKey.String())
	c.cidQueue.AddAfter(cidKey, delay)
}
