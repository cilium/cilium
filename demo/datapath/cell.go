package datapath

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"datapath",
	"Demo Datapath",

	// Frontends state, BPF map and reconciliation.
	// Provides 'Frontends' API for querying and manipulating the desired
	// state.
	frontendsCell,

	// Backends state, BPF map and reconciliation.
	// Provides 'Backends' API for querying and manipulating the desired
	// state.
	backendsCell,
)
