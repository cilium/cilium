package controlplane

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"controlplane",
	"Demo control-plane",

	tablesCell,
	controllersCell,
)
