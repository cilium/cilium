// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

var _ netlinkFuncs = (*netlink.Handle)(nil)

type netlinkFuncs interface {
	RouteGetWithOptions(destination net.IP, options *netlink.RouteGetOptions) ([]netlink.Route, error)
	NeighSet(neigh *netlink.Neigh) error
	NeighDel(neigh *netlink.Neigh) error
}

type netlinkFuncsGetter struct {
	funcs netlinkFuncs
}

func newNetlinkFuncsGetter(lifecycle cell.Lifecycle) *netlinkFuncsGetter {
	n := &netlinkFuncsGetter{}

	lifecycle.Append(
		cell.Hook{
			OnStart: func(_ cell.HookContext) error {
				// Get a netlink handle in the current namespace.
				// Otherwise we default to the namespace at startup. Which is not what we want
				// during testing where we might currently be in a sub-namespace.
				handle, err := netlink.NewHandle()
				if err != nil {
					return fmt.Errorf("creating netlink handle: %w", err)
				}

				n.funcs = handle
				return nil
			},
		},
	)

	return n
}

func (n *netlinkFuncsGetter) Get() netlinkFuncs {
	return n.funcs
}

func newOps(
	neighbors statedb.Table[*tables.Neighbor],
	desiredNeighbors statedb.Table[*DesiredNeighbor],
	funcsGetter *netlinkFuncsGetter,
	config *CommonConfig,
	metrics *neighborMetrics,
) reconciler.Operations[*DesiredNeighbor] {
	return &ops{
		neighbors:       neighbors,
		desiredNeighbor: desiredNeighbors,
		funcsGetter:     funcsGetter,
		config:          config,
		metrics:         metrics,
	}
}

var _ reconciler.Operations[*DesiredNeighbor] = (*ops)(nil)

type ops struct {
	neighbors       statedb.Table[*tables.Neighbor]
	desiredNeighbor statedb.Table[*DesiredNeighbor]
	funcsGetter     *netlinkFuncsGetter
	config          *CommonConfig
	metrics         *neighborMetrics
}

// Update gets called with a new desired neighbor (or when one is updated).
func (ops *ops) Update(ctx context.Context, rx statedb.ReadTxn, _ statedb.Revision, neighbor *DesiredNeighbor) error {
	ops.metrics.NeighborEntryInsertCount.Inc()

	_, _, isNew := ops.neighbors.Get(rx, tables.NeighborIDIndex.Query(tables.NeighborID{
		IPAddr:    neighbor.IP,
		LinkIndex: neighbor.IfIndex,
	}))

	neigh := netlink.Neigh{
		LinkIndex:    neighbor.IfIndex,
		IP:           neighbor.IP.AsSlice(),
		Flags:        netlink.NTF_EXT_LEARNED | netlink.NTF_USE,
		HardwareAddr: nil,
	}
	if ops.config.ARPPingKernelManaged() == nil {
		neigh.Flags = netlink.NTF_EXT_LEARNED
		neigh.FlagsExt = netlink.NTF_EXT_MANAGED
	} else if isNew {
		// Quirk for older kernels above. We cannot directly create a
		// dynamic NUD_* with NTF_EXT_LEARNED|NTF_USE without having
		// the following kernel fixes:
		//   e4400bbf5b15 ("net, neigh: Fix NTF_EXT_LEARNED in combination with NTF_USE")
		//   3dc20f4762c6 ("net, neigh: Enable state migration between NUD_PERMANENT and NTF_USE")
		// Thus, first initialize the neighbor as NTF_EXT_LEARNED and
		// then do the subsequent ping via NTF_USE.
		//
		// Notes on use of the NUD_STALE state. We have three scenarios:
		// 1) Old entry was a PERMANENT one. In this case, the kernel
		// takes the PERMANENT's lladdr in __neigh_update() and uses
		// it for temporary STALE state. This ensures that whoever
		// does a lookup in this short window can continue keep using
		// the lladdr. The subsequent NTF_USE will trigger a fresh
		// resolution in neigh_event_send() given STALE dictates it
		// (as opposed to REACHABLE).
		// 2) Old entry was a dynamic + externally learned one. This
		// is similar as the PERMANENT one if the entry was NUD_VALID
		// before. The subsequent NTF_USE will trigger a new resolution.
		// 3) Old entry was non-existent. Given we don't push down a
		// corresponding lladdr, the neighbor entry gets created by the
		// kernel, but given prior state was not NUD_VALID then the
		// __neigh_update() will error out (EINVAL). However, the entry
		// is in the kernel, and subsequent NTF_USE will trigger a proper
		// resolution. Hence, below NeighSet() does _not_ bail out given
		// errors are expected in this case.
		neighInit := netlink.Neigh{
			LinkIndex:    neighbor.IfIndex,
			IP:           neighbor.IP.AsSlice(),
			State:        netlink.NUD_STALE,
			Flags:        netlink.NTF_EXT_LEARNED,
			HardwareAddr: nil,
		}
		if err := ops.funcsGetter.Get().NeighSet(&neighInit); err != nil {
			// EINVAL is expected (see above)
			if errors.Is(err, unix.EINVAL) {
				return nil
			}

			return fmt.Errorf("next hop initial insert failed for %+v: %w", neighInit, err)
		}
	}
	if err := ops.funcsGetter.Get().NeighSet(&neigh); err != nil {
		return fmt.Errorf("next hop refresh failed for %+v: %w", neigh, err)
	}

	return nil
}

// Delete gets called with a deleted desired neighbor.
func (ops *ops) Delete(ctx context.Context, rx statedb.ReadTxn, _ statedb.Revision, neighbor *DesiredNeighbor) error {
	neigh, _, found := ops.neighbors.Get(rx, tables.NeighborIDIndex.Query(tables.NeighborID{
		IPAddr:    neighbor.IP,
		LinkIndex: neighbor.IfIndex,
	}))
	if !found {
		return nil
	}

	ops.metrics.NeighborEntryDeleteCount.Inc()

	err := ops.funcsGetter.Get().NeighDel(&netlink.Neigh{
		LinkIndex:    neigh.LinkIndex,
		IP:           neigh.IPAddr.AsSlice(),
		Flags:        int(neigh.Flags),
		FlagsExt:     int(neigh.FlagsExt),
		HardwareAddr: nil,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// The neighbor entry was already deleted
			return nil
		}

		return err
	}

	return nil
}

// Prune any neighbor entries in the kernel not in the desired neighbors table.
func (ops *ops) Prune(ctx context.Context, rx statedb.ReadTxn, _ iter.Seq2[*DesiredNeighbor, statedb.Revision]) error {
	var errs error
	for actualNeighbor := range ops.neighbors.All(rx) {
		ciliumManaged := actualNeighbor.Flags&netlink.NTF_EXT_LEARNED > 0
		if !ciliumManaged {
			continue
		}

		_, _, found := ops.desiredNeighbor.Get(rx, DesiredNeighborIndex.Query(DesiredNeighborKey{
			IP:      actualNeighbor.IPAddr,
			IfIndex: actualNeighbor.LinkIndex,
		}))
		if found {
			continue
		}

		ops.metrics.NeighborEntryDeleteCount.Inc()

		err := ops.funcsGetter.Get().NeighDel(&netlink.Neigh{
			LinkIndex:    actualNeighbor.LinkIndex,
			IP:           actualNeighbor.IPAddr.AsSlice(),
			Flags:        int(actualNeighbor.Flags),
			FlagsExt:     int(actualNeighbor.FlagsExt),
			HardwareAddr: nil,
		})
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				// The neighbor entry was already deleted
				continue
			}

			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func newNeighborReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*DesiredNeighbor],
	tbl statedb.RWTable[*DesiredNeighbor],
	config *CommonConfig,
) (reconciler.Reconciler[*DesiredNeighbor], error) {
	if !config.Enabled {
		// If L2 neighbor discovery is disabled, we don't need to run the reconciler.
		return nil, nil
	}

	return reconciler.Register(
		params,
		tbl,
		(*DesiredNeighbor).Clone,
		(*DesiredNeighbor).SetStatus,
		(*DesiredNeighbor).GetStatus,
		ops,
		nil, // no batch ops

		reconciler.WithRefreshing(0, nil), // no automatic refresh, we have custom refresh logic
	)
}

func newNeighborRefresher(
	db *statedb.DB,
	neighbors statedb.Table[*tables.Neighbor],
	desiredNeighbors statedb.RWTable[*DesiredNeighbor],
	jobGroup job.Group,
	metrics *neighborMetrics,
	config *CommonConfig,
) {
	if !config.Enabled {
		// If L2 neighbor discovery is disabled, we don't need to run the refresher.
		return
	}

	jobGroup.Add(
		job.OneShot("neighbor-refresher", func(ctx context.Context, health cell.Health) error {
			tx := db.WriteTxn(neighbors)
			changes, err := neighbors.Changes(tx)
			if err != nil {
				tx.Abort()
				return fmt.Errorf("subscribing to neighbor changes: %w", err)
			}
			tx.Commit()

			// Limit the rate at which the change batches are processed.
			// A second seems like a reasonable time for refreshing neighbor entries.
			limiter := rate.NewLimiter(1*time.Second, 1)
			defer limiter.Stop()

			for {
				rx := db.ReadTxn()

				events, watch := changes.Next(rx)

				// Keep a list of neighbors to refresh. To keep the write transaction
				// short.
				var toRefresh []*DesiredNeighbor

				for neighborEvent := range events {
					neighbor := neighborEvent.Object

					if !neighborEvent.Deleted {
						// Don't look at neighbors that are not owned by Cilium.
						ciliumOwned := neighbor.Flags&netlink.NTF_EXT_LEARNED > 0
						if !ciliumOwned {
							continue
						}

						// If the neighbor is managed by the kernel, we don't need to refresh it.
						// The kernel will handle refreshing it automatically.
						kernelManaged := neighbor.FlagsExt&netlink.NTF_EXT_MANAGED > 0
						if kernelManaged {
							continue
						}

						// If the neighbor entry got upserted but is not stale, we don't need to refresh it.
						stale := neighbor.State == netlink.NUD_STALE
						if !stale {
							continue
						}
					}

					// If we are here, we have a non-kernel-managed neighbor that is stale or
					// a neighbor that has been deleted. We unconditionally consult the desired neighbors
					// table on deletes since we may not be able to see if the deleted neighbor entry
					// was cilium owned and or kernel managed.

					desiredNeighbor, _, found := desiredNeighbors.Get(rx, DesiredNeighborIndex.Query(DesiredNeighborKey{
						IP:      neighbor.IPAddr,
						IfIndex: neighbor.LinkIndex,
					}))
					if found {
						toRefresh = append(toRefresh, desiredNeighbor)
					}
				}

				metrics.NeighborEntryRefreshCount.Add(float64((len(toRefresh))))

				var errs error
				// Set the status of these desired neighbors to refreshing, as signal to the
				// reconciler to refresh them.
				tx := db.WriteTxn(desiredNeighbors)
				for _, neighbor := range toRefresh {
					_, _, err := desiredNeighbors.Insert(tx, neighbor.SetStatus(reconciler.StatusRefreshing()))
					errs = errors.Join(errs, err)
				}
				tx.Commit()

				if errs != nil {
					health.Degraded("failed to refresh one or more neighbors", errs)
				} else {
					health.OK(fmt.Sprintf("refreshed %d neighbors", len(toRefresh)))
				}

				select {
				case <-ctx.Done():
					return nil
				case <-watch:
					// Limit the rate of the loop so we process in batches
					limiter.Wait(ctx)
					continue
				}
			}
		}),
	)
}
