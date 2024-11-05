// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"strconv"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CID controller also watches for CESs. The only reason is to keep a cache of
// what CIDs are used in CESs. This is required only when CESs are enabled.
// CID controller won't delete a CID until it is no longer present in any CESs.
func (c *Controller) processCiliumEndpointSliceEvents(ctx context.Context) error {
	if !c.cesEnabled {
		return nil
	}

	for event := range c.ciliumEndpointSlice.Events(ctx) {
		var idsWithNoCESUsage []int64

		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert CES event", logfields.CESName, event.Key.String())
			idsWithNoCESUsage = c.reconciler.cidUsageInCES.ProcessCESUpsert(event.Object.Name, event.Object.Endpoints)
		case resource.Delete:
			c.logger.Debug("Got Delete CES event", logfields.CESName, event.Key.String())
			idsWithNoCESUsage = c.reconciler.cidUsageInCES.ProcessCESDelete(event.Object.Name, event.Object.Endpoints)
		}

		for _, cid := range idsWithNoCESUsage {
			cidName := strconv.Itoa(int(cid))
			c.logger.Info("Reconciling CID as it is no longer used in CESs", logfields.CIDName, cidName)
			c.enqueueReconciliation(CIDItem{cidResourceKey(cidName)}, 0)
		}

		event.Done(nil)
	}
	return nil
}
