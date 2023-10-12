package reconcilers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/reconciler"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var RoutesCell = cell.Module(
	"routes",
	"Routing table reconciliation",

	statedb.NewProtectedTableCell[*DesiredRoute](
		"desired-routes",
		RouteIDIndex,
		RouteOwnerIndex,
		RouteStatusIndex,
	),

	cell.Provide(newRoutes),

	// FIXME. Should be provided by e.g. datapath cell.
	cell.Provide(func() *netns.NsHandle {
		ns := netns.None()
		return &ns
	}),

	// Provide the dependencies to the reconciler.
	cell.ProvidePrivate(
		// Construct the route reconciliation target against the target
		// network namespace. It uses the device and route tables to
		// efficiently check for existence.
		func(log logrus.FieldLogger, ns *netns.NsHandle,
			devices statedb.Table[*tables.Device],
			routes statedb.Table[*tables.Route],
		) (reconciler.Target[*DesiredRoute], error) {
			h, err := netlink.NewHandleAt(*ns)
			if err != nil {
				return nil, err
			}
			return &routeTestTarget{log, h, devices, routes}, nil
		},
		func() reconciler.Config {
			return reconciler.Config{
				FullReconcilationInterval: 10 * time.Second,
				RetryBackoffMinDuration:   time.Second,
				RetryBackoffMaxDuration:   10 * time.Second,
			}
		},

		reconciler.New[*DesiredRoute],
	),

	// Provide a job group for this module.
	cell.ProvidePrivate(job.Registry.NewGroup),
	cell.Invoke(func(lc hive.Lifecycle, g job.Group) { lc.Append(g) }),

	// Trigger synchronization when devices change to react to
	// devices changing state.
	cell.Invoke(syncOnDeviceChanges),
)

// syncOnDeviceChanges triggers full reconciliation when devices change.
// This allows quickly reacting to flapping device state that causes routes
// to get flushed.
func syncOnDeviceChanges(
	jobs job.Group,
	db *statedb.DB,
	devices statedb.Table[*tables.Device],
	reconciler reconciler.Reconciler[*DesiredRoute],
) {
	limiter := rate.NewLimiter(30*time.Second, 2)
	jobs.Add(job.OneShot(
		"sync-routes-on-device-changes",
		func(ctx context.Context) error {
			for {
				limiter.Wait(ctx)
				_, watch := tables.SelectedDevices(
					devices,
					db.ReadTxn(),
				)
				// FIXME actually check if relevant things changed as
				// there's no guarantee that the watch channel closed
				// due to a relevant change.
				select {
				case <-ctx.Done():
					return nil
				case <-watch:
				}
				reconciler.TriggerSync()
			}
		},
	))
}

//
// The Route API
//

type Routes struct {
	db      *statedb.DB
	table   statedb.RWTable[*DesiredRoute]
	devices statedb.Table[*tables.Device]
}

type RoutesHandle struct {
	owner string
	r     Routes
}

func newRoutes(db *statedb.DB, table statedb.RWTable[*DesiredRoute], devices statedb.Table[*tables.Device]) Routes {
	return Routes{db, table, devices}
}

func (r Routes) NewHandle(name string) RoutesHandle {
	return RoutesHandle{name, r}
}

func (h RoutesHandle) InsertLegacy(route route.Route) error {
	// TODO: Should we deal here with device names or indexes?
	// Existing code mostly deals with names, so this just
	// resolves the index on the fly here, which of course
	// can fail.

	// TODO: There are way too many 'Route' types. Need to trim
	// it down. Unify "route.Route" and "tables.Route". Would not
	// depend on "netlink" library and would try to keep it somewhat
	// Linux independent if possible.

	txn := h.r.db.WriteTxn(h.r.table)
	defer txn.Abort()

	var gw netip.Addr
	if route.Nexthop != nil {
		// TODO errs
		gw, _ = ip.AddrFromIP(*route.Nexthop)
	}
	dstAddr, _ := ip.AddrFromIP(route.Prefix.IP)
	dstBits, _ := route.Prefix.Mask.Size()
	dst := netip.PrefixFrom(
		dstAddr,
		dstBits,
	)

	if route.Table == 0 {
		// In existing code the routing table seems to be left unset, which then
		// defaults to the main table when added. In the desired route we need
		// the proper table as otherwise we cannot look up actual routes.
		route.Table = unix.RT_TABLE_MAIN
	}

	dev, _, ok := h.r.devices.First(txn, tables.DeviceNameIndex.Query(route.Device))
	if !ok {
		return errors.New("device not found")
	}

	_, _, err := h.r.table.Insert(txn,
		&DesiredRoute{
			Owner: h.owner,
			Route: tables.Route{
				Table:     route.Table,
				LinkIndex: dev.Index,
				MTU:       route.MTU,
				Scope:     uint8(route.Scope),
				Priority:  route.Priority,
				Dst:       dst,
				Gw:        gw,
			},
			Status: reconciler.StatusPending(),
		})
	if err != nil {
		return err
	}

	txn.Commit()
	return nil

}

func (h RoutesHandle) DeleteLegacy(route route.Route) error {
	dstAddr, _ := ip.AddrFromIP(route.Prefix.IP)
	dstBits, _ := route.Prefix.Mask.Size()
	dst := netip.PrefixFrom(
		dstAddr,
		dstBits,
	)

	if route.Table == 0 {
		// In existing code the routing table seems to be left unset, which then
		// defaults to the main table when added. In the desired route we need
		// the proper table as otherwise we cannot look up actual routes.
		route.Table = unix.RT_TABLE_MAIN
	}

	txn := h.r.db.WriteTxn(h.r.table)
	defer txn.Abort()

	dev, _, ok := h.r.devices.First(txn, tables.DeviceNameIndex.Query(route.Device))
	if !ok {
		return errors.New("device not found")
	}

	iter, _ := h.r.table.Get(txn, RouteOwnerIndex.Query(h.owner))
	for r, _, ok := iter.Next(); ok; r, _, ok = iter.Next() {
		if r.Route.Dst == dst && r.Route.LinkIndex == dev.Index {
			h.r.table.Insert(
				txn,
				r.WithStatus(reconciler.StatusPendingDelete()))
		}

	}
	txn.Commit()
	return nil
}

func (h RoutesHandle) Insert(route tables.Route) bool {
	// TODO: Where would we handle the automatic "next hop" creation
	// logic done in route_linux.go?

	// TODO: How do we deal with overlapping routes coming from
	// different handles?

	txn := h.r.db.WriteTxn(h.r.table)
	_, hadOld, _ := h.r.table.Insert(txn,
		&DesiredRoute{
			Owner:  h.owner,
			Route:  route,
			Status: reconciler.StatusPending(),
		})
	txn.Commit()
	return hadOld
}

func (h RoutesHandle) Delete(route tables.Route) bool {
	txn := h.r.db.WriteTxn(h.r.table)
	entry, _, ok := h.r.table.First(txn,
		RouteIDIndex.Query(
			tables.RouteID{Table: route.Table,
				LinkIndex: route.LinkIndex,
				Dst:       route.Dst,
			}))
	if ok {
		h.r.table.Insert(
			txn,
			entry.WithStatus(reconciler.StatusPendingDelete()))
	}
	txn.Commit()
	return ok
}

func (h RoutesHandle) DeleteAll() {
	txn := h.r.db.WriteTxn(h.r.table)
	iter, _ := h.r.table.Get(txn, RouteOwnerIndex.Query(h.owner))
	for route, _, ok := iter.Next(); ok; route, _, ok = iter.Next() {
		h.r.table.Insert(
			txn,
			route.WithStatus(reconciler.StatusPendingDelete()))
	}
	txn.Commit()
}

func (h RoutesHandle) Wait(ctx context.Context) error {
	// TODO: Return error(s) from status if ctx cancelled?
	for {
		txn := h.r.db.ReadTxn()
		iter, watch := h.r.table.Get(txn, RouteOwnerIndex.Query(h.owner))
		done := true
		for route, _, ok := iter.Next(); ok; route, _, ok = iter.Next() {
			if route.Status.Kind != reconciler.StatusKindDone {
				done = false
				break
			}
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
	}
}

//
// Route setting and indexes
//

type DesiredRoute struct {
	Owner  string
	Route  tables.Route
	Status reconciler.Status
}

func (s *DesiredRoute) PrimaryKey() []byte {
	return s.RouteID().Key()
}

func (s *DesiredRoute) RouteID() tables.RouteID {
	return tables.RouteID{
		Table:     s.Route.Table,
		LinkIndex: s.Route.LinkIndex,
		Dst:       s.Route.Dst,
	}
}

func (s *DesiredRoute) GetStatus() reconciler.Status {
	return s.Status
}

func (s *DesiredRoute) WithStatus(newStatus reconciler.Status) *DesiredRoute {
	s2 := *s
	s2.Status = newStatus
	return &s2
}

func (d *DesiredRoute) toNetlinkRoute() *netlink.Route {
	return &netlink.Route{
		Table:     d.Route.Table,
		LinkIndex: d.Route.LinkIndex,
		Dst:       prefixToIPNet(d.Route.Dst),
		Src:       d.Route.Src.AsSlice(),
		Gw:        d.Route.Gw.AsSlice(),
		Scope:     netlink.Scope(d.Route.Scope), // TODO validate?
		Protocol:  linux_defaults.RTProto,       // TODO configurable?
		MTU:       d.Route.MTU,
	}
}

var (
	RouteIDIndex = statedb.Index[*DesiredRoute, tables.RouteID]{
		Name: "id",
		FromObject: func(s *DesiredRoute) index.KeySet {
			return index.NewKeySet(s.PrimaryKey())
		},
		FromKey: tables.RouteID.Key,
		Unique:  true,
	}
	RouteOwnerIndex = statedb.Index[*DesiredRoute, string]{
		Name: "owner",
		FromObject: func(s *DesiredRoute) index.KeySet {
			return index.NewKeySet(index.String(s.Owner))
		},
		FromKey: index.String,
		Unique:  false,
	}
	RouteStatusIndex = reconciler.NewStatusIndex[*DesiredRoute]()
)

//
// Route reconciliation target
//

type routeTestTarget struct {
	log           logrus.FieldLogger
	netlinkHandle *netlink.Handle
	devices       statedb.Table[*tables.Device]
	routes        statedb.Table[*tables.Route]
}

func (routeTestTarget) Init(context.Context) error {
	return nil
}

func (t *routeTestTarget) Delete(_ context.Context, txn statedb.ReadTxn, desired *DesiredRoute) error {
	t.log.Infof("Delete: %v\n", desired)

	if err := t.netlinkHandle.RouteDel(desired.toNetlinkRoute()); err != nil {
		// FIXME handle ENOEXIST type error as ok (if there's a need)
		return fmt.Errorf("failed to delete route to %q owned by %q: %w",
			desired.Route.Dst.String(),
			desired.Owner,
			err)
	}
	return nil
}

// Sync implements reconciler.Target
func (t *routeTestTarget) Sync(ctx context.Context, txn statedb.ReadTxn, iter statedb.Iterator[*DesiredRoute]) (outOfSync bool, err error) {
	t.log.Infof("Sync")

	var errs []error

	for desired, _, ok := iter.Next(); ok; desired, _, ok = iter.Next() {
		if _, _, ok := t.routes.First(txn, tables.RouteIDIndex.Query(desired.RouteID())); ok {
			continue
		}

		t.log.Infof("Sync: desired route %v not found", desired)

		outOfSync = true

		if err := t.Update(ctx, txn, desired); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		err = errors.Join(errs...)
	}

	return
}

// Update implements reconciler.Target
func (t *routeTestTarget) Update(_ context.Context, txn statedb.ReadTxn, desired *DesiredRoute) error {
	t.log.Infof("Update: %v\n", desired)
	if _, _, ok := t.routes.First(txn, tables.RouteIDIndex.Query(desired.RouteID())); ok {
		// FIXME: Need further checks to see that e.g. MTU matches and so on.
		t.log.Infof("Update: %v already exists, nothing to do\n", desired)
		return nil
	}
	t.log.Infof("Update: %v does not exist, adding\n", desired)

	if err := t.netlinkHandle.RouteReplace(desired.toNetlinkRoute()); err != nil {
		return fmt.Errorf("failed to replace route to %q owned by %q: %w",
			desired.Route.Dst.String(),
			desired.Owner,
			err)
	}
	return nil
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	if !prefix.IsValid() {
		return nil
	}
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

var _ reconciler.Target[*DesiredRoute] = &routeTestTarget{}
