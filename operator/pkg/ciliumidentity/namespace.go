// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/sirupsen/logrus"
)

func (c *Controller) processNamespaceEvents(ctx context.Context) error {
	for event := range c.namespaces.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.K8sNamespace: event.Key.String()}).Debug("Got Upsert Namespace event")
			c.onNamespaceUpsert(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// onNamespaceUpsert sends namespace to Cilium Identity for reconciliation if
// the namespace labels are changed.
func (c *Controller) onNamespaceUpsert(ns *slim_core_v1.Namespace) {
	newLabels := getNamespaceLabels(ns)

	oldIdtyLabels := c.oldNSSecurityLabels[ns.Name]
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)

	// Do not perform any other operations if labels did not change.
	if oldIdtyLabels.DeepEqual(&newIdtyLabels) {
		return
	}

	c.oldNSSecurityLabels[ns.Name] = newIdtyLabels
	c.reconciler.reconcileNS(nsResourceKey(ns.Name))
}

func getNamespaceLabels(ns *slim_core_v1.Namespace) labels.Labels {
	lbls := ns.GetLabels()
	labelMap := make(map[string]string, len(lbls))
	for k, v := range lbls {
		labelMap[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	return labels.Map2Labels(labelMap, labels.LabelSourceK8s)
}

func nsResourceKey(namespace string) resource.Key {
	return resource.Key{Name: namespace}
}
