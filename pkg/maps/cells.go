// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell contains all cells which are providing BPF Maps.
var Cell = cell.Module(
	"maps",
	"BPF Maps",
)
