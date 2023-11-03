// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"datapath-tables",
	"Datapath state tables",

	L2AnnounceTableCell,
	NodeAddressCell,
)
