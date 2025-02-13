// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// Cell implements the processing of the CiliumLocalRedirectPolicy CRD.
// For each policy it creates a pseudo-service with suffix -local-redirect
// and associates to it all matching local pods as backends. The service
// frontends that are being redirected will then take the backends of the
// pseudo-service.
var Cell = cell.Module(
	"local-redirect-policies",
	"Controller for CiliumLocalRedirectPolicy",

	cell.ProvidePrivate(
		// Provide the (RW)Table[*LocalRedirectPolicy]
		NewLRPTable,
		statedb.RWTable[*LocalRedirectPolicy].ToTable,
	),

	cell.ProvidePrivate(
		newLRPListerWatcher,
		newLRPIsEnabled,
	),

	cell.Invoke(
		// Reflect the CiliumLocalRedirectPolicy CRDs into Table[*LocalRedirectPolicy]
		registerLRPReflector,

		// Register a controller to process the changes in the LRP, pod and frontend
		// tables.
		registerLRPController,
	),
)
