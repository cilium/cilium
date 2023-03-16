// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

var Cell = cell.Module("maps", "Maps",
	ipcache.Cell,
)
