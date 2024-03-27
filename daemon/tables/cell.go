package tables

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"controlplane-tables",
	"Agent control-plane StateDB tables",

	ServicesCell,
	K8sReflectorCell,
)
