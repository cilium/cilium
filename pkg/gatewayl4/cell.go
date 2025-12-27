// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gatewayl4

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// Cell provides the Gateway L4 config table and its k8s reflector.
var Cell = cell.Module(
	"gateway-l4",
	"Gateway L4 config table and reflector",
	tableCells,
	controllerCells,
)

var tableCells = cell.Group(
	cell.ProvidePrivate(
		NewGatewayL4Table,
		gatewayL4ListerWatchers,
	),
	cell.Provide(
		statedb.RWTable[*GatewayL4Config].ToTable,
	),
	cell.Invoke(
		registerGatewayL4K8sReflector,
	),
)

var controllerCells = cell.Group(
	cell.Invoke(
		registerGatewayL4Controller,
	),
)
