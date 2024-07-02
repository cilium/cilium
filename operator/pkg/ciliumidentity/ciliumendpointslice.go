// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"strconv"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert CES event",
				logfields.CESName, event.Key.String())
			c.onCiliumEndpointSliceUpsert(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete CES event",
				logfields.CESName, event.Key.String())
			c.onCiliumEndpointSliceDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// onCiliumEndpointSliceUpsert updates cache for CID usage in CES based on the
// CES upsert event and then sends CIDs that are no longer used in CESs to get
// reconciled. Expected action of CID reconciliation is for CID to be deleted.
func (c *Controller) onCiliumEndpointSliceUpsert(ces *v2alpha1.CiliumEndpointSlice) {
	if ces == nil {
		return
	}

	idsWithNoICESUsage := c.reconciler.cidUsageInCES.ProcessCESUpsert(ces.Name, ces.Endpoints)

	for _, cid := range idsWithNoICESUsage {
		cidName := strconv.Itoa(int(cid))

		c.logger.Info("Reconciling CID as it is no longer used in CESs", logfields.CIDName, cidName)
		c.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
	}
}

// onCiliumEndpointSliceDelete updates cache for CID usage in CES based on the
// CES delete event and then sends CIDs that are no longer used in CESs to get
// reconciled. Expected action of CID reconiliation is for CID to be deleted.
func (c *Controller) onCiliumEndpointSliceDelete(ces *v2alpha1.CiliumEndpointSlice) {
	if ces == nil {
		return
	}

	idsWithNoICESUsage := c.reconciler.cidUsageInCES.ProcessCESDelete(ces.Name, ces.Endpoints)

	for _, cid := range idsWithNoICESUsage {
		cidName := strconv.Itoa(int(cid))

		c.logger.Info("Reconcile CID as it is no longer used in CESs", logfields.CIDName, cidName)
		c.enqueueCIDReconciliation(cidResourceKey(cidName), 0)
	}
}
