// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func cidResourceKey(cidName string) resource.Key {
	return resource.Key{Name: cidName}
}

type CIDItem struct {
	key resource.Key
}

func (c CIDItem) Key() resource.Key {
	return c.key
}

func (c *Controller) processCiliumIdentityEvents(ctx context.Context) error {
	for event := range c.ciliumIdentity.Events(ctx) {
		if event.Kind == resource.Upsert || event.Kind == resource.Delete {
			c.logger.Debug("Got CID event", logfields.Type, event.Kind, logfields.CIDName, event.Key.String())
			c.enqueueReconciliation(CIDItem{cidResourceKey(event.Object.Name)}, 0)
		}
		event.Done(nil)
	}
	return nil
}
