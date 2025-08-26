// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"iter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
)

func registerReconciler(
	params reconciler.Params,
	tbl statedb.RWTable[*DesiredRoute],
) (reconciler.Reconciler[*DesiredRoute], error) {
	return reconciler.Register(
		params,
		tbl,
		(*DesiredRoute).Clone,
		(*DesiredRoute).SetStatus,
		(*DesiredRoute).GetStatus,
		newOps(params.Lifecycle, params.DB, tbl),
		nil, // No batch operations
	)
}

func newOps(
	lifecycle cell.Lifecycle,
	db *statedb.DB,
	tbl statedb.Table[*DesiredRoute],
) reconciler.Operations[*DesiredRoute] {
	ops := &ops{
		db:  db,
		tbl: tbl,
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			var err error
			ops.handle, err = netlink.NewHandle()
			return err
		},
	})

	return ops
}

type ops struct {
	db     *statedb.DB
	tbl    statedb.Table[*DesiredRoute]
	handle *netlink.Handle
}

func (ops *ops) Update(_ context.Context, rxn statedb.ReadTxn, _ statedb.Revision, obj *DesiredRoute) error {
	// If the route is not selected, we do not need to update it.
	if !obj.selected {
		return nil
	}

	return ops.handle.RouteReplace(desiredRouteToNetlinkRoute(obj))
}

func (ops *ops) Delete(_ context.Context, rxn statedb.ReadTxn, _ statedb.Revision, obj *DesiredRoute) error {
	// If the route is not selected, we do not need to delete it.
	if !obj.selected {
		return nil
	}

	return ops.handle.RouteDel(desiredRouteToNetlinkRoute(obj))
}

func (ops *ops) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*DesiredRoute, statedb.Revision]) error {
	// TODO implement
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
