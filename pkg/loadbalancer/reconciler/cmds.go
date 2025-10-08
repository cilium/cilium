// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

type scriptCommandsParams struct {
	cell.In

	Config            loadbalancer.Config
	TestConfig        *loadbalancer.TestConfig `optional:"true"`
	ReconcilerPromise promise.Promise[reconciler.Reconciler[*loadbalancer.Frontend]]
	BPFOps            *BPFOps
}

func scriptCommands(p scriptCommandsParams) hive.ScriptCmdsOut {
	cmds := map[string]script.Cmd{
		"lb/prune": script.Command(
			script.CmdUsage{Summary: "Trigger pruning of load-balancing BPF maps"},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				r, err := p.ReconcilerPromise.Await(s.Context())
				if err != nil {
					return nil, err
				}

				count := p.BPFOps.pruneCount.Load()
				r.Prune()

				// Wait for prune to happen
				for s.Context().Err() != nil || p.BPFOps.pruneCount.Load() <= count {
					time.Sleep(10 * time.Millisecond)
				}
				return nil, s.Context().Err()
			},
		),
	}
	return hive.NewScriptCmds(cmds)
}
