// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

func (c *Controller) processPodEvents(ctx context.Context) error {
	for event := range c.pod.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.K8sPodName: event.Key.String()}).Debug("Got Upsert Pod event")
			c.onPodUpdate(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.K8sPodName: event.Key.String()}).Debug("Got Upsert Pod event")
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
	c.logger.WithFields(logrus.Fields{
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CID controller workqueue configuration for Pod")

	c.podQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff), "pod")
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same Pod at the
// same time.
func (c *Controller) runPodWorker(ctx context.Context) error {
	c.logger.Infof("Starting Pod worker in CID controller")
	defer c.logger.Infof("Stopping Pod worker in CID controller")

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
		if exists {
			enqueuedLatency := processingStartTime.Sub(enqueueTime).Seconds()
			c.metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValuePodWorkqueue, LabelValueEnqueuedLatency).Observe(enqueuedLatency)
		}
		processingLatency := time.Since(processingStartTime).Seconds()
		c.metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValuePodWorkqueue, LabelValueProcessingLatency).Observe(processingLatency)
	}

	return true
}

func (c *Controller) handlePodErr(err error, item interface{}) {
	if err == nil {
		if operatorOption.Config.EnableMetrics {
			c.metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValuePodWorkqueue, metrics.LabelValueOutcomeSuccess).Inc()
		}

		c.podQueue.Forget(item)
		return
	}

	if operatorOption.Config.EnableMetrics {
		c.metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValuePodWorkqueue, metrics.LabelValueOutcomeFail).Inc()
	}

	c.logger.Infof("Failed to process Pod: %v", err)

	if c.podQueue.NumRequeues(item) < maxProcessRetries {
		c.podQueue.AddRateLimited(item)
		return
	}

	// Drop the pod from queue, we maxed out retries.
	c.logger.WithError(err).WithFields(logrus.Fields{
		logfields.K8sPodName: item,
	}).Error("Dropping the Pod from queue, exceeded maxRetries")
	c.podQueue.Forget(item)
}

func podResourceKey(podName, podNamespace string) resource.Key {
	return resource.Key{Name: podName, Namespace: podNamespace}
}

func (c *Controller) enqueuePodReconciliation(podKey resource.Key, delay time.Duration) {
	if len(podKey.String()) == 0 {
		return
	}

	c.podEnqueuedAt.SetEnqueueTimeIfNotSet(podKey.String())
	c.podQueue.AddAfter(podKey, delay)
}
