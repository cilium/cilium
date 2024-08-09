// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"

	k8s "github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (c *Controller) processNamespaceEvents(ctx context.Context) error {

	//store, _ := c.namespace.Store(c.context)
	//for _, ns := range store.List() {
	//	c.onNamespaceUpsert(ns)
	//}

	for event := range c.namespace.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Namespace event ", logfields.K8sNamespace, event.Key.String())

			c.onNamespaceUpsert(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Upsert Namespace event ", logfields.K8sNamespace, event.Key.String())

			c.onNamespaceDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// onNamespaceEvent sends namespace to Cilium Identity for reconciliation if
// the namespace labels are changed.
func (c *Controller) onNamespaceUpsert(ns *slimcorev1.Namespace) {
	value, _ := k8s.Get(ns, "cilium.io/ces-namespace")
	if value == "priority" {
		c.logger.Infof("Namespace has a priority annotation %s", ns.Name)
		c.priorityNamespaces[ns.Name] = 1
	} else {
		c.logger.Infof("Namespace does not have priority: %s", ns.Name)
		delete(c.priorityNamespaces, ns.Name)
	}
}

func (c *Controller) onNamespaceDelete(ns *slimcorev1.Namespace) {

	c.logger.Infof("Namespace deleted: %s", ns.Name)
	delete(c.priorityNamespaces, ns.Name)

}
