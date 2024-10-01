// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/datapath/types"
)

var Cell = cell.Module(
	"orchestrator",
	"Orchestrator",

	cell.Config(DefaultConfig),
	cell.Provide(NewOrchestrator),
)

func NewOrchestrator(params orchestratorParams) (types.Orchestrator, hive.ScriptCmdOut) {
	o := newOrchestrator(params)
	cmd := hive.NewScriptCmd(
		"orchestrator",
		script.Command(
			script.CmdUsage{Summary: "Show orchestrator state"},
			o.showLatestConfigurationCmd,
		),
	)
	return o, cmd
}
