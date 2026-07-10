// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"github.com/cilium/hive/cell"

	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
)

var Cell = cell.Module(
	"orchestrator",
	"Orchestrator",

	cell.Config(DefaultConfig),
	cell.Provide(NewOrchestrator),
)

func NewOrchestrator(params orchestratorParams) endpoint.Orchestrator {
	return newOrchestrator(params)
}
