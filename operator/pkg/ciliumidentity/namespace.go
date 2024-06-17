// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

func nsResourceKey(namespace string) resource.Key {
	return resource.Key{Name: namespace}
}

func (c *Controller) processNamespaceEvents(ctx context.Context) error {
	for event := range c.namespace.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Namespace event", logfields.K8sNamespace, event.Key.String())

			c.onNamespaceEvent(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// onNamespaceEvent sends namespace to Cilium Identity for reconciliation if
// the namespace labels are changed.
func (c *Controller) onNamespaceEvent(ns *slimcorev1.Namespace) {
	newLabels := getNamespaceLabels(ns)

	oldIdLabels := c.oldNSSecurityLabels[ns.Name]
	newIdLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations if labels did not change.
	if oldIdLabels.DeepEqual(&newIdLabels) {
		return
	}

	c.oldNSSecurityLabels[ns.Name] = newIdLabels

	if err := c.reconciler.reconcileNamespace(nsResourceKey(ns.Name)); err != nil {
		c.logger.Error("Failed to process namespaces changes", logfields.K8sNamespace, ns.Name, logfields.Error, err)
	}
}

func getNamespaceLabels(ns *slimcorev1.Namespace) labels.Labels {
	lbs := ns.GetLabels()
	labelMap := make(map[string]string, len(lbs))
	for k, v := range lbs {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}
