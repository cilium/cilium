// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"strings"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/identity/key"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
)

func (c *Controller) processCiliumIdentityEvents(ctx context.Context) error {
	for event := range c.ciliumIdentities.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Cilium Identity event")
			c.onCiliumIdentityUpsert(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Cilium Identity event")
			c.onCiliumIdentityDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) onCiliumIdentityUpsert(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name))
}

func (c *Controller) onCiliumIdentityDelete(cid *cilium_api_v2.CiliumIdentity) {
	c.enqueueCIDReconciliation(cidResourceKey(cid.Name))
}

func (c *Controller) initCIDQueue() {
	if c.cidQueueQpsLimit <= 0 {
		c.cidQueueQpsLimit = defaultCIDQueueQPSLimit
	}

	if c.cidQueueBurstLimit <= 0 {
		c.cidQueueBurstLimit = defaultCIDQueueBurstLimit
	}

	c.logger.WithFields(logrus.Fields{
		logfields.WorkQueueQPSLimit:    c.cidQueueQpsLimit,
		logfields.WorkQueueBurstLimit:  c.cidQueueBurstLimit,
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("Cilium Identity controller workqueue configuration for Cilium Identity")

	c.cidQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff), "cilium_identity")
	c.cidQueueRateLimiter = rate.NewLimiter(rate.Limit(c.cidQueueQpsLimit), c.cidQueueBurstLimit)
}

func (c *Controller) rateLimitCIDProcessing() {
	delay := c.cidQueueRateLimiter.Reserve().Delay()

	if operatorOption.Config.EnableMetrics {
		c.metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueRateLimitLatency).Observe(delay.Seconds())
	}

	select {
	case <-c.context.Done():
	case <-time.After(delay):
	}
}

// runWorker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same CID
// at the same time
func (c *Controller) runCIDWorker(ctx context.Context) error {
	c.logger.Infof("Starting Cilium Identity worker in Cilium Identity controller")
	defer c.logger.Infof("Stopping Cilium Identity worker in Cilium Identity controller")

	running := true

	for running {
		select {
		case <-ctx.Done():
			running = false
		default:
			running = c.processNextCIDQueueItem()
		}
	}

	return nil
}

func (c *Controller) processNextCIDQueueItem() bool {
	c.rateLimitCIDProcessing()

	processingStartTime := time.Now()

	item, quit := c.cidQueue.Get()
	if quit {
		return false
	}
	defer c.cidQueue.Done(item)

	cidItem := item.(queueItem)
	err := c.reconciler.reconcileCID(cidItem.key)
	c.handleCIDErr(err, item)

	if operatorOption.Config.EnableMetrics {
		enqueuedLatency := processingStartTime.Sub(cidItem.enqueueTime).Seconds()
		c.metrics.CIDControllerWorkqueueLatency.WithLabelValues(LabelValueCIDWorkqueue, LabelValueEnqueuedLatency).Observe(enqueuedLatency)

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

	c.logger.Infof("Failed to process Cilium Identity: %v", err)

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

func (c *Controller) enqueueCIDReconciliation(cidKey resource.Key) {
	if len(cidKey.String()) == 0 {
		return
	}

	item := queueItem{
		key:         cidKey,
		enqueueTime: time.Now(),
	}

	c.cidQueue.Add(item)
}

func GetCIDKeyFromK8sLabels(k8sLabels map[string]string) *key.GlobalIdentity {
	lbls := labels.Map2Labels(k8sLabels, labels.LabelSourceK8s)
	idLabels, _ := labelsfilter.Filter(lbls)
	return &key.GlobalIdentity{LabelArray: idLabels.LabelArray()}
}

func GetCIDKeyFromSecurityLabels(secLabels map[string]string) *key.GlobalIdentity {
	lbls := labels.Map2Labels(secLabels, "")
	idLabels, _ := labelsfilter.Filter(lbls)
	return &key.GlobalIdentity{LabelArray: idLabels.LabelArray()}
}

func GetIDRelevantLabelsFromConfigMap(ctx context.Context, clientset k8sClient.Clientset) ([]string, error) {
	maxRetries := 5
	waitDuration := 1 * time.Second
	attempt := 1

	var cm *corev1.ConfigMap
	var err error
	for attempt <= maxRetries {
		cm, err = clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(ctx, ciliumConfigMapName, metav1.GetOptions{})
		if err == nil {
			break
		}

		time.Sleep(waitDuration)
		attempt++
	}

	if err != nil {
		return nil, err
	}

	// Turns a string into a string slice. Whitespaces separate filter entries.
	// https://docs.cilium.io/en/stable/operations/performance/scalability/identity-relevant-labels/
	filter := strings.Fields(cm.Data[idRelevantLabelsKey])
	return filter, nil
}
