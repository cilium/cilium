// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nonglobal

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

var (
	// defaultSyncBackOff is the default backoff period for cesSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cesSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a cesSync will be retried before it is
	// dropped out of the queue.
	maxProcessRetries = 15
)

func (l *LocalOnlyCachingIDAllocator) initEndpointQueue() {
	log.WithFields(logrus.Fields{
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("Workqueue configuration for endpoints, part of non global security identity allocator controller")

	l.endpointQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff), "endpoint")
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same endpoint
// at the same time
func (l *LocalOnlyCachingIDAllocator) runEndpointWorker() {
	for l.processNextEndpointQueueItem() {
	}
}

func (l *LocalOnlyCachingIDAllocator) processNextEndpointQueueItem() bool {
	item, quit := l.endpointQueue.Get()
	if quit {
		return false
	}
	defer l.endpointQueue.Done(item)

	var err error
	ep, ok := item.(*endpoint.Endpoint)
	if ok {
		err = l.ReconcileSecIDForEndpoint(ep)
	} else {
		err = fmt.Errorf("failed to convert endpoint queue item, expected *endpoint.Endpoint, got %T", item)
	}

	if metrics.LocalEndpointIDReconcileTotal.IsEnabled() {
		if err != nil {
			metrics.LocalEndpointIDReconcileTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		} else {
			metrics.LocalEndpointIDReconcileTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
		}
	}

	l.handleEndpointErr(err, item, ep)
	return true
}

func (l *LocalOnlyCachingIDAllocator) handleEndpointErr(err error, item interface{}, ep *endpoint.Endpoint) {
	if err == nil {
		l.endpointQueue.Forget(item)
		return
	}

	log.Infof("Failed to process endpoint: %v", err)

	if l.endpointQueue.NumRequeues(item) < maxProcessRetries {
		l.endpointQueue.AddRateLimited(item)
		return
	}

	// Drop the endpoint from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		logfields.EndpointID: ep.ID,
	}).Error("Dropping the endpoint from queue, exceeded maxRetries")
	l.endpointQueue.Forget(item)
}

func (l *LocalOnlyCachingIDAllocator) enqueueEndpointReconciliation(ep *endpoint.Endpoint) {
	if ep == nil {
		return
	}
	l.endpointQueue.Add(ep)
}
