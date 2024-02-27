// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"orchestrator",
	"Orchestrator",

	cell.Provide(NewOrchestrator),
	cell.ProvidePrivate(newRealNetlink),
)

func NewOrchestrator(params orchestratorParams) types.Orchestrator {
	return newOrchestrator(params)
}
