// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/cmd/cni"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module(
	"orchestrator",
	"Orchestrator",

	cell.Config(DefaultConfig),
	cell.Provide(NewOrchestrator),

	// Resolved by the orchestrator, awaited by the CNI configuration manager.
	cell.Provide(promise.New[cni.DatapathReady]),
)

func NewOrchestrator(params orchestratorParams) endpoint.Orchestrator {
	return newOrchestrator(params)
}
