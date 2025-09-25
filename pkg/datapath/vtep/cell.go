// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"datapath-vtep",
	"VTEP Manager",

	cell.Provide(newVTEPManager),
)
