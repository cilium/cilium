// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wal"
)

func registerReconciler(
	params reconciler.Params,
	tbl statedb.RWTable[*DesiredRoute],
	devices statedb.Table[*tables.Device],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredRoute], error) {
	return reconciler.Register(
		params,
		tbl,
		(*DesiredRoute).Clone,
		(*DesiredRoute).SetStatus,
		(*DesiredRoute).GetStatus,
		newOps(params.Lifecycle, params.DB, tbl, devices, log, config),
		nil, // No batch operations
		reconciler.WithPruning(30*time.Minute),
	)
}

func newOps(
	lifecycle cell.Lifecycle,
	db *statedb.DB,
	tbl statedb.Table[*DesiredRoute],
	devices statedb.Table[*tables.Device],
	log *slog.Logger,
	conf *option.DaemonConfig,
) reconciler.Operations[*DesiredRoute] {
	ops := &ops{
		db:      db,
		tbl:     tbl,
		devices: devices,
		log:     log,

		persistedKeys: make(map[DesiredRouteKey]struct{}),
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			var err error
			ops.handle, err = netlink.NewHandle()
			if err != nil {
				return err
			}

			walPath := filepath.Join(conf.StateDir, "route-reconciler.wal")

			// Read all old route keys from the WAL.
			events, err := wal.Read(walPath, func(data []byte) (reconcilerEvent, error) {
				var key reconcilerEvent
				if err := key.UnmarshalBinary(data); err != nil {
					return reconcilerEvent{}, err
				}
				return key, nil
			})
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			} else {
				for oldRouteKey, err := range events {
					if err != nil {
						ops.log.Error("Failed to read old route key from WAL", logfields.Error, err)
						continue
					}

					if oldRouteKey.Deleted {
						delete(ops.persistedKeys, oldRouteKey.Key)
					} else {
						ops.persistedKeys[oldRouteKey.Key] = struct{}{}
					}
				}
			}

			ops.wal, err = wal.NewWriter[reconcilerEvent](walPath)
			if err != nil {
				return err
			}

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			if ops.handle != nil {
				ops.handle.Close()
				ops.handle = nil
			}
			if ops.wal != nil {
				ops.wal.Close()
			}
			return nil
		},
	})

	return ops
}

type reconcilerEvent struct {
	Deleted bool
	Key     DesiredRouteKey
}

func (e reconcilerEvent) MarshalBinary() ([]byte, error) {
	var buf []byte
	if e.Deleted {
		buf = append(buf, byte(1))
	} else {
		buf = append(buf, byte(0))
	}

	keyBuf, err := e.Key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, keyBuf...)

	return buf, nil
}

func (e *reconcilerEvent) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return nil
	}

	if data[0] == byte(1) {
		e.Deleted = true
	} else {
		e.Deleted = false
	}

	if err := e.Key.UnmarshalBinary(data[1:]); err != nil {
		return err
	}

	return nil
}

type ops struct {
	db      *statedb.DB
	tbl     statedb.Table[*DesiredRoute]
	devices statedb.Table[*tables.Device]
	log     *slog.Logger

	handle        *netlink.Handle
	wal           *wal.Writer[reconcilerEvent]
	persistedKeys map[DesiredRouteKey]struct{}
}

var errDeviceNotFound = errors.New("device no longer exists")

func (ops *ops) Update(_ context.Context, rxn statedb.ReadTxn, _ statedb.Revision, obj *DesiredRoute) error {
	// If the route is not selected, we do not need to update it.
	if !obj.selected {
		return nil
	}

	if obj.Device != nil {
		// Verify that the device still exists.
		_, _, found := ops.devices.Get(rxn, tables.DeviceIDIndex.Query(obj.Device.Index))
		if !found {
			return errDeviceNotFound
		}
	}

	// Write to the WAL first, then update the route in the kernel.
	// If we crash after writing to the WAL but before updating the route, no harm done.
	err := ops.wal.Write(reconcilerEvent{
		Deleted: false,
		Key:     obj.GetOwnerlessKey(),
	})
	if err != nil {
		return fmt.Errorf("failed to write update event to WAL: %w", err)
	}

	return ops.handle.RouteReplace(desiredRouteToNetlinkRoute(obj))
}

func (ops *ops) Delete(_ context.Context, rxn statedb.ReadTxn, _ statedb.Revision, obj *DesiredRoute) error {
	// If the route is not selected, we do not need to delete it.
	if !obj.selected {
		return nil
	}

	// First delete the route from the kernel, then write to the WAL.
	// If we crash after deleting the route but before writing to the WAL, we will
	// re-try the deletion on restart, which is safe.
	err2 := ops.handle.RouteDel(desiredRouteToNetlinkRoute(obj))

	err := ops.wal.Write(reconcilerEvent{
		Deleted: true,
		Key:     obj.GetOwnerlessKey(),
	})
	if err != nil {
		return fmt.Errorf("failed to write delete event to WAL: %w", err)
	}

	return err2
}

func (ops *ops) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*DesiredRoute, statedb.Revision]) error {
	// If we have a set of keys from a previous run, we need to check if we still desire them.
	// If not, we need to delete any route that we previously installed but no longer desire.
	if len(ops.persistedKeys) != 0 {
		for key := range ops.persistedKeys {
			_, _, found := ops.tbl.Get(txn, DesiredRouteTablePrefixIndex.Query(key))
			if !found {
				routes, _ := safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
					//nolint:forbidigo
					return ops.handle.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{
						Table:    int(key.Table),
						Dst:      netipx.PrefixIPNet(key.Prefix),
						Priority: int(key.Priority),
					}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_PRIORITY)
				})
				for _, r := range routes {
					ops.handle.RouteDel(&r)
				}
			}
		}

		ops.persistedKeys = nil
	}

	// Compact the WAL, replace log with only currently selected and active routes.
	ops.wal.Compact(func(yield func(reconcilerEvent) bool) {
		for obj := range objects {
			if !obj.selected {
				continue
			}
			if obj.GetStatus().Kind != reconciler.StatusKindDone {
				continue
			}

			if !yield(reconcilerEvent{
				Deleted: false,
				Key:     obj.GetOwnerlessKey(),
			}) {
				return
			}
		}
	})

	return nil
}

func desiredRouteToNetlinkRoute(route *DesiredRoute) *netlink.Route {
	nlRoute := &netlink.Route{
		Table: int(route.Table),
		Dst:   netipx.PrefixIPNet(route.Prefix),
	}

	if route.Nexthop.IsValid() {
		nlRoute.Gw = route.Nexthop.AsSlice()
	}

	if route.Src.IsValid() {
		nlRoute.Src = route.Src.AsSlice()
	}

	if route.Device != nil {
		nlRoute.LinkIndex = int(route.Device.Index)
	}

	if route.MTU != 0 {
		nlRoute.MTU = int(route.MTU)
	}

	if route.Priority != 0 {
		nlRoute.Priority = int(route.Priority)
	}

	// Set protocol to 'kernel'. systemd-networkd, by default, will prune any routes that it did not create.
	// Routes marked with RTPROT_KERNEL are not pruned by systemd-networkd because these are normally created by the
	// kernel itself. We need to hide out routes amongst the kernel routes to prevent systemd-networkd from pruning them.
	// See https://www.freedesktop.org/software/systemd/man/latest/networkd.conf.html#ManageForeignRoutingPolicyRules=
	nlRoute.Protocol = netlink.RouteProtocol(2) // RTPROT_KERNEL

	if route.Scope != SCOPE_UNIVERSE {
		nlRoute.Scope = netlink.Scope(route.Scope)
	} else if route.Scope == SCOPE_UNIVERSE && route.Type == RTN_LOCAL {
		nlRoute.Scope = netlink.SCOPE_HOST
	}

	if route.Type != 0 {
		nlRoute.Type = int(route.Type)
	}

	return nlRoute
}
