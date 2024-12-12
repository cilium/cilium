// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"os"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb/reconciler"
)

func scriptCommands(cfg Config, m LBMaps, r reconciler.Reconciler[*Frontend]) hive.ScriptCmdsOut {
	if !cfg.EnableExperimentalLB {
		return hive.ScriptCmdsOut{}
	}

	var snapshot mapSnapshots
	return hive.NewScriptCmds(map[string]script.Cmd{
		"lb/prune": script.Command(
			script.CmdUsage{Summary: "Trigger pruning of load-balancing BPF maps"},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				r.Prune()
				return nil, nil
			},
		),
		"lb/maps-dump":     lbmapDumpCommand(m),
		"lb/maps-snapshot": lbmapSnapshotCommand(m, &snapshot),
		"lb/maps-restore":  lbmapRestoreCommand(m, &snapshot),
	})
}

func lbmapDumpCommand(m LBMaps) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the load-balancing BPF maps",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the load-balancer BPF maps either to stdout or to a file.",
				"Each BPF map key-value is shown as one line, e.g. backend would be:",
				"BE: ID=1 ADDR=10.244.1.1:80 STATE=active",
				"",
				"Format is not guaranteed to be stable as this command is only",
				"for testing and debugging purposes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				out := DumpLBMaps(
					m,
					false,
					nil,
				)
				data := strings.Join(out, "\n") + "\n"
				if len(args) == 1 {
					err = os.WriteFile(s.Path(args[0]), []byte(data), 0644)
				} else {
					stdout = data
				}
				return
			}, nil
		},
	)
}

func lbmapSnapshotCommand(m LBMaps, snapshot *mapSnapshots) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Snapshot the load-balancing BPF maps",
			Args:    "",
			Detail: []string{
				"Dump the load-balancing BPF maps into an in-memory snapshot",
				"which can be restored with lbmaps/restore. This is meant only",
				"for testing.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, snapshot.snapshot(m)
		},
	)
}

func lbmapRestoreCommand(m LBMaps, snapshot *mapSnapshots) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Restore the load-balancing BPF maps from snapshot",
			Args:    "",
			Detail: []string{
				"Restore the load-balancing BPF map contents from a snapshot",
				"created with lbmaps/snapshot.",
				"The BPF maps are not cleared before restoring, so any existing",
				"values will not be removed.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, snapshot.restore(m)
		},
	)
}
