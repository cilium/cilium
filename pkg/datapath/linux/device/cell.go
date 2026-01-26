// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

var Cell = cell.Module(
	"device-reconciler",
	"Reconciles desired devices to the Linux kernel links",
	TableCell,
	cell.Provide(newDeviceManager),
	cell.Invoke(registerReconciler),
)

var TableCell = cell.Group(
	cell.ProvidePrivate(newDesiredDeviceTable),
	cell.Provide(statedb.RWTable[*DesiredDevice].ToTable),
)
