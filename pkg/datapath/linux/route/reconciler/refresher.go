// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

func desiredRouteRefresher(
	jobGroup job.Group,
	db *statedb.DB,
	desiredRoutes statedb.RWTable[*DesiredRoute],
	routes statedb.Table[*tables.Route],
	devices statedb.Table[*tables.Device],
) {
	jobGroup.Add(job.OneShot(
		"desired-route-refresher",
		func(ctx context.Context, health cell.Health) error {
			txn := db.WriteTxn(routes, devices)
			routeIter, err := routes.Changes(txn)
			if err != nil {
				txn.Abort()
				return err
			}
			devicesIter, err := devices.Changes(txn)
			if err != nil {
				txn.Abort()
				return err
			}
			txn.Commit()

			// Limit the rate at which the change batches are processed.
			// A second seems like a reasonable time for refreshing neighbor entries.
			limiter := rate.NewLimiter(1*time.Second, 1)
			defer limiter.Stop()

			for {
				txn := db.WriteTxn(desiredRoutes)
				routeChanges, routeWait := routeIter.Next(txn)
				deviceChanges, deviceWait := devicesIter.Next(txn)

				for routeChange := range routeChanges {
					// Get the desired routes that match the changed route.
					changedDesiredRoutes := desiredRoutes.List(txn, DesiredRouteTablePrefixIndex.Query(DesiredRouteKey{
						Table:    TableID(routeChange.Object.Table),
						Prefix:   routeChange.Object.Dst,
						Priority: uint32(routeChange.Object.Priority),
					}))

					// Loop over any desired routes that match the changed route.
					for desiredRoute := range changedDesiredRoutes {
						// If the desired route is not selected, skip it.
						if !desiredRoute.selected {
							continue
						}

						// If the route has been deleted we always need to refresh the desired route.
						// If the route was changed, we only need to refresh if the desired route
						// does not equal the actual route anymore.
						if !routeChange.Deleted && equal(desiredRoute, routeChange.Object) {
							continue
						}

						desiredRoutes.Insert(txn, desiredRoute.SetStatus(reconciler.StatusRefreshing()))
					}
				}

				for deviceChange := range deviceChanges {
					// We only care about deleted devices.
					if !deviceChange.Deleted {
						continue
					}

					// If a device was deleted, we need to refresh any desired routes
					// that were using this device.
					for dr := range desiredRoutes.All(txn) {
						if dr.Device != nil && int(dr.Device.Index) == deviceChange.Object.Index {
							desiredRoutes.Insert(txn, dr.SetStatus(reconciler.StatusRefreshing()))
						}
					}
				}
				txn.Commit()

				// Limit the rate at which we process changes.
				limiter.Wait(ctx)

				// Wait for the next change, or context cancellation.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-routeWait:
				case <-deviceWait:
				}
			}
		},
	))
}

func equal(desired *DesiredRoute, actual *tables.Route) bool {
	if desired.Table != TableID(actual.Table) {
		return false
	}
	if desired.Prefix != actual.Dst {
		return false
	}
	if desired.Priority != uint32(actual.Priority) {
		return false
	}

	if uint16(desired.Type) != uint16(actual.Type) {
		return false
	}
	if desired.Scope != Scope(actual.Scope) {
		return false
	}
	if desired.Src.Compare(actual.Src) != 0 {
		return false
	}
	if desired.Nexthop.Compare(actual.Gw) != 0 {
		return false
	}
	if (desired.Device == nil && actual.LinkIndex != 0) ||
		(desired.Device != nil && int(desired.Device.Index) != actual.LinkIndex) {
		return false
	}
	if desired.MTU != uint32(actual.MTU) {
		return false
	}
	return true
}
