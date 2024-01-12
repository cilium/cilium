package controlplane

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"controlplane",
	"Demo control-plane",

	// Control-plane tables (Table[*Service] and Table[*Endpoint])
	tablesCell,

	// K8s to statedb reflectors
	k8sCell,

	// HTTP API handlers
	handlersCell,

	// Controller for computing frontends and backends from services and endpoints
	servicesControllerCell,
)
