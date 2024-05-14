// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/types"
)

// Orchestrator bridges the agent state to the loader, watching inputs
// and reinitializing when they change.
var Cell = cell.Module(
	"orchestrator",
	"Orchestrator",

	cell.Provide(NewOrchestrator),
)

func NewOrchestrator(params orchestratorParams) types.Orchestrator {
	return newOrchestrator(params)
}
