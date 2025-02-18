// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/server/restapi/service"
)

// Cell implements the processing of the CiliumLocalRedirectPolicy CRD.
// For each policy it creates a pseudo-service with suffix -local-redirect
// and associates to it all matching local pods as backends. The service
// frontends that are being redirected will then take the backends of the
// pseudo-service.
var Cell = cell.Module(
	"local-redirect-policies",
	"Controller for CiliumLocalRedirectPolicy",

	cell.Provide(
		newLRPIsEnabled,

		NewLRPTable,
		statedb.RWTable[*LocalRedirectPolicy].ToTable,

		newLRPListerWatcher,

		newDesiredSkipLBTable,
		newSkipLBMap,
	),

	cell.Provide(
		// Provide the 'skiplbmap' command for inspecting SkipLBMap.
		newSkipLBMapCommand,
	),

	cell.Invoke(
		// Reflect the CiliumLocalRedirectPolicy CRDs into Table[*LocalRedirectPolicy]
		registerLRPReflector,

		// Register a controller to process the changes in the LRP, pod and frontend
		// tables.
		registerLRPController,

		// Register the SkipLBMap recnociler and the endpoint subscriber for pulling
		// pod netns cookies
		registerSkipLB,
	),

	// Replace the REST API implementation if enabled
	cell.DecorateAll(replaceAPI),
)

func replaceAPI(enabled lrpIsEnabled, old service.GetLrpHandler, db *statedb.DB, lrps statedb.Table[*LocalRedirectPolicy]) service.GetLrpHandler {
	if !enabled {
		return old
	}
	return &getLrpHandler{db, lrps}
}
