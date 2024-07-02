// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"

	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"

	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func podResourceKey(podName, podNamespace string) resource.Key {
	return resource.Key{Name: podName, Namespace: podNamespace}
}

func (c *Controller) processPodEvents(ctx context.Context) error {
	for event := range c.pod.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Pod event",
				logfields.K8sPodName, event.Key.String())

			c.onPodUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete Pod event",
				logfields.K8sPodName, event.Key.String())

			c.onPodUpdate(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// onPodUpdate pushes a CID create to the CID work queue if there is no matching
// CID for the security labels.
func (c *Controller) onPodUpdate(pod *slim_core_v1.Pod) {
	c.enqueuePodReconciliation(podResourceKey(pod.Name, pod.Namespace), 0)
}

func (c *Controller) initPodQueue() {
	c.logger.Info("CID controller work queue configuration for Pod",
		logfields.WorkQueueSyncBackOff, defaultSyncBackOff)

	c.podQueue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		workqueue.RateLimitingQueueConfig{Name: "pod"})
}

// runPodWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// work queue guarantees that they will not end up processing the same Pod at the
// same time.
func (c *Controller) runPodWorker(_ context.Context) error {
	c.logger.Info("Starting Pod worker")
	defer c.logger.Info("Stopping Pod worker")

	for c.processNextPodQueueItem() {
		select {
		case <-c.context.Done():
			return nil
		default:
		}
	}

	return nil
}

func (c *Controller) processNextPodQueueItem() bool {
	processingStartTime := time.Now()

	item, quit := c.podQueue.Get()
	if quit {
		return false
	}
	defer c.podQueue.Done(item)

	podKey := item.(resource.Key)

	err := c.reconciler.reconcilePod(podKey)
	c.handlePodErr(err, item)

	if operatorOption.Config.EnableMetrics {
		enqueueTime, exists := c.podEnqueuedAt.GetEnqueueTimeAndReset(podKey.String())
		c.metrics.meterLatency(LabelValuePodWorkQueue, processingStartTime, exists, enqueueTime)
	}

	return true
}

func (c *Controller) handlePodErr(err error, item interface{}) {
	if operatorOption.Config.EnableMetrics {
		c.metrics.markEvent(LabelValuePodWorkQueue, err == nil)
	}

	if err == nil {
		c.podQueue.Forget(item)
		return
	}

	c.logger.Error("Failed to process Pod", logfields.Error, err)

	if c.podQueue.NumRequeues(item) < maxProcessRetries {
		c.podQueue.AddRateLimited(item)
		return
	}

	// Drop the pod from queue, exceeded max retries
	c.logger.Error("Dropping the Pod from queue, exceeded maxRetries",
		logfields.K8sPodName, item,
		logfields.Error, err)

	c.podQueue.Forget(item)
}

func (c *Controller) enqueuePodReconciliation(podKey resource.Key, delay time.Duration) {
	if len(podKey.String()) == 0 {
		return
	}

	c.podEnqueuedAt.SetEnqueueTimeIfNotSet(podKey.String())
	c.podQueue.AddAfter(podKey, delay)
}
