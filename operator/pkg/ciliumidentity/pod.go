// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func podResourceKey(podName, podNamespace string) resource.Key {
	return resource.Key{Name: podName, Namespace: podNamespace}
}

type PodItem struct {
	key resource.Key
}

func (p PodItem) Key() resource.Key {
	return p.key
}

func (p PodItem) Reconcile(reconciler *reconciler) error {
	return reconciler.reconcilePod(p.key)
}

func (c *Controller) processPodEvents(ctx context.Context) error {
	for event := range c.pod.Events(ctx) {
		if event.Kind == resource.Upsert || event.Kind == resource.Delete {
			c.logger.Debug("Got Pod event", logfields.Type, event.Kind, logfields.K8sPodName, event.Key.String())
			c.enqueueReconciliation(PodItem{podResourceKey(event.Object.Name, event.Object.Namespace)}, 0)
		}
		event.Done(nil)
	}
	return nil
}
