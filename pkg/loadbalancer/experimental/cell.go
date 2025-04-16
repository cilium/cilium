// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"errors"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/netns"
)

var Cell = cell.Module(
	"loadbalancer",
	"Experimental load-balancing control-plane",

	cell.Config(DefaultConfig),
	cell.Provide(newExternalConfig),

	// Provides [Writer] API and the load-balancing tables.
	TablesCell,

	// ReconcilerCell reconciles the load-balancing state with the BPF maps.
	ReconcilerCell,

	// Provide [lbmaps], abstraction for the load-balancing BPF map access.
	cell.ProvidePrivate(newLBMaps),

	// Provide the 'lb/' script commands for debugging and testing.
	cell.Provide(scriptCommands),

	// Health server runs an HTTP server for each service on port [HealthCheckNodePort]
	// (when non-zero) and responds with the number of healthy backends.
	healthServerCell,

	// Register a background job to re-reconcile NodePort and HostPort frontends when
	// the node addresses change.
	cell.Invoke(registerNodePortAddressReconciler),

	// Register a background job to watch for node zone label changes.
	cell.Invoke(registerNodeZoneWatcher),

	// Replace the [k8s.ServiceCacheReader] and [service.ServiceReader] if this
	// implementation is enabled.
	cell.Provide(newAdapters),
	cell.DecorateAll(decorateAdapters),

	// Provide [HaveNetNSCookieSupport] to probe for netns cookie support.
	cell.Provide(NetnsCookieSupportFunc),
)

// TablesCell provides the [Writer] API for configuring load-balancing and the
// Table[*Service], Table[*Frontend] and Table[*Backend] for read-only access
// to load-balancing state.
var TablesCell = cell.Module(
	"loadbalancer-tables",
	"Tables for load-balancing",

	// Provide the RWTable[Service] and RWTable[Backend] privately to this
	// module so that the tables are only modified via the Services API.
	cell.ProvidePrivate(
		NewServicesTable,
		NewFrontendsTable,
		NewBackendsTable,
	),

	cell.Provide(
		// Provide the [Writer] API for modifying the tables.
		NewWriter,

		// Provide direct read-only access to the tables.
		toReadOnlyTable[*Service],
		toReadOnlyTable[*Frontend],
		toReadOnlyTable[*Backend],
	),
)

func toReadOnlyTable[T any](tbl statedb.RWTable[T]) statedb.Table[T] {
	if tbl == nil {
		return nil
	}
	return tbl
}

type HaveNetNSCookieSupport func() bool

func NetnsCookieSupportFunc() HaveNetNSCookieSupport {
	return sync.OnceValue(func() bool {
		_, err := netns.GetNetNSCookie()
		return !errors.Is(err, unix.ENOPROTOOPT)
	})
}
