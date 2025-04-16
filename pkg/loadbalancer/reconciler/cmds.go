// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

type scriptCommandsParams struct {
	cell.In

	Config     loadbalancer.Config
	TestConfig *loadbalancer.TestConfig `optional:"true"`
	Reconciler reconciler.Reconciler[*loadbalancer.Frontend]
}

func scriptCommands(p scriptCommandsParams) hive.ScriptCmdsOut {
	if !p.Config.EnableExperimentalLB {
		return hive.ScriptCmdsOut{}
	}
	cmds := map[string]script.Cmd{
		"lb/prune": script.Command(
			script.CmdUsage{Summary: "Trigger pruning of load-balancing BPF maps"},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				p.Reconciler.Prune()
				return nil, nil
			},
		),
	}
	return hive.NewScriptCmds(cmds)
}
