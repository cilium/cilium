package ciliumidentity

import (
	"context"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/ciliumconfig"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	ciliumConfigMapName = "cilium-config"
	idRelevantLabelsKey = "labels"
)

func (c *Controller) processCiliumIdentityEvents(ctx context.Context) error {
	for event := range c.ciliumIdentity.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Cilium Identity event")
			c.onCiliumIdentityUpsertEvent(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Cilium Identity event")
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
	c.logger.WithFields(logrus.Fields{
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CID controller workqueue configuration for Cilium Identity")

	c.cidQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff), "cilium_identity")
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same CID
// at the same time
func (c *Controller) runCIDWorker(ctx context.Context) error {
	c.logger.Infof("Starting CID worker in CID controller")
	defer c.logger.Infof("Stopping CID worker in CID controller")

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
	processingStartTime := time.Now()

	item, quit := c.cidQueue.Get()
	if quit {
		return false
	}
	defer c.cidQueue.Done(item)

	cidKey := item.(resource.Key)
	err := c.reconciler.reconcileCID(cidKey)
	c.handleCIDErr(err, item)

	if operatorOption.Config.EnableMetrics {
		enqueueTime, exists := c.cidEnqueuedAt.GetEnqueueTimeAndReset(cidKey.String())
		if exists {
			enqueuedLatency := processingStartTime.Sub(enqueueTime).Seconds()
			c.metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueEnqueuedLatency).Observe(enqueuedLatency)
		}
		processingLatency := time.Since(processingStartTime).Seconds()
		c.metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueProcessingLatency).Observe(processingLatency)
	}

	return true
}

func (c *Controller) handleCIDErr(err error, item interface{}) {
	if err == nil {
		if operatorOption.Config.EnableMetrics {
			c.metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValueCIDWorkqueue, metrics.LabelValueOutcomeSuccess).Inc()
		}

		c.cidQueue.Forget(item)
		return
	}

	if operatorOption.Config.EnableMetrics {
		c.metrics.CIDControllerWorkqueueEventCount.WithLabelValues(LabelValueCIDWorkqueue, metrics.LabelValueOutcomeFail).Inc()
	}

	c.logger.WithField(logfields.CIDName, item).Errorf("Failed to process Cilium Identity: %v", err)

	if c.cidQueue.NumRequeues(item) < maxProcessRetries {
		c.cidQueue.AddRateLimited(item)
		return
	}

	// Drop the CID from queue, we maxed out retries.
	c.logger.WithError(err).WithFields(logrus.Fields{
		logfields.CIDName: item,
	}).Error("Dropping the Cilium Identity from queue, exceeded maxRetries")
	c.cidQueue.Forget(item)
}

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}

func (c *Controller) enqueueCIDReconciliation(cidKey resource.Key, delay time.Duration) {
	if len(cidKey.String()) == 0 {
		return
	}

	c.cidEnqueuedAt.SetEnqueueTimeIfNotSet(cidKey.String())
	c.cidQueue.AddAfter(cidKey, delay)
}

func (c *Controller) getIDRelevantLabelsFilter() ([]string, error) {
	cm, err := ciliumconfig.GetCiliumConfig(c.context, c.clientset)
	if err != nil {
		return nil, err
	}

	if cm.Data == nil {
		return nil, nil
	}

	// Turns a string into a string slice. Whitespaces separate filter entries.
	// https://docs.cilium.io/en/stable/operations/performance/scalability/identity-relevant-labels/
	filter := strings.Fields(cm.Data[idRelevantLabelsKey])
	c.logger.Infof("Identity relevant labels filter: %v", filter)

	return filter, nil
}
