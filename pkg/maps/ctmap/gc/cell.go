// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"ct-nat-map-gc",
	"Garbage collection of CT and NAT maps",

	cell.Provide(
		// Provide the interface uses to start the GC logic. This hack
		// should be removed once all dependencies have been modularized,
		// and we can start the GC through a Start hook.
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
