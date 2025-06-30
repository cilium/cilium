// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/types"
)

var Cell = cell.Module(
	"orchestrator",
	"Orchestrator",

	cell.Config(DefaultConfig),
	cell.Provide(NewOrchestrator),
)

func NewOrchestrator(params orchestratorParams) types.Orchestrator {
	return newOrchestrator(params)
}
