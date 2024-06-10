// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
)

var Cell = cell.Module(
	"ct-nat-map-gc",
	"Garbage collection of CT and NAT maps",

	cell.Provide(
		// Provide the interface uses to start the GC logic. This hack
		// should be removed once all dependencies have been modularized,
		// and we can start the GC through a Start hook.
		// TODO: GH-33557: Add a hook for purge events to replace ctmap.PurgeHook.
		func(gc *GC) Enabler { return gc },
	),

	cell.ProvidePrivate(
		New,

		// Register the signal handler for CT and NAT fill-up signals.
		newSignalHandler,
		// Provide the reduced interface used by the GC logic.
		func(mgr endpointmanager.EndpointManager) EndpointManager { return mgr },
	),
)
