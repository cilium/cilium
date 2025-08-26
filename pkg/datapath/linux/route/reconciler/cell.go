// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

var Cell = cell.Module(
	"route-reconciler",
	"Reconciles desired routes to the Linux kernel routing table",
	TableCell,
	cell.Invoke(registerReconciler),
)

var TableCell = cell.Group(
	cell.Provide(newDesiredRouteManager),
	cell.ProvidePrivate(newDesiredRouteTable),
	cell.Provide(statedb.RWTable[*DesiredRoute].ToTable),
)
