// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/scaletozero"
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

		"lb/scale-to-zero-dump": scaleToZeroDumpCommand(p.BPFOps.scaleToZeroMap),
	}
	return hive.NewScriptCmds(cmds)
}

func scaleToZeroDumpCommand(m scaletozero.Map) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the services tracked for scale-to-zero",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the services that opted into scale-to-zero either to",
				"stdout or to a file. Each service is shown as one line with the",
				"identifier it has in the load-balancing BPF maps, e.g.:",
				"SCALETOZERO: ID=1",
				"",
				"Format is not guaranteed to be stable as this command is only",
				"for testing and debugging purposes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				var ids []loadbalancer.ServiceID
				if err = m.Dump(func(id loadbalancer.ServiceID, _ uint64) {
					ids = append(ids, id)
				}); err != nil {
					return
				}
				slices.Sort(ids)

				var b strings.Builder
				for _, id := range ids {
					fmt.Fprintf(&b, "SCALETOZERO: ID=%d\n", id)
				}

				if len(args) == 1 {
					err = os.WriteFile(s.Path(args[0]), []byte(b.String()), 0644)
				} else {
					stdout = b.String()
				}
				return
			}, nil
		},
	)
}
