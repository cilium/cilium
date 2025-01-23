// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/pflag"
)

func scriptCommands(
	cfg Config, db *statedb.DB, w *Writer,
	m LBMaps, r reconciler.Reconciler[*Frontend],
) hive.ScriptCmdsOut {
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

type enumValue[S ~string] struct {
	p    *S
	alts []S
}

func newEnumValue[S ~string](val S, alts []S, p *S) *enumValue[S] {
	*p = val
	return &enumValue[S]{
		p:    p,
		alts: alts,
	}
}

func (ev *enumValue[S]) Type() string {
	var v S
	return fmt.Sprintf("%T", v)
}

func (ev *enumValue[S]) Set(val string) error {
	val = strings.ToLower(val)
	for _, alt := range ev.alts {
		if strings.ToLower(string(alt)) == val {
			*ev.p = alt
			return nil
		}
	}
	return fmt.Errorf("%q not found from alternatives %v", val, ev.alts)
}

func (ev *enumValue[S]) String() string {
	if ev == nil || ev.p == nil {
		return ""
	}
	return string(*ev.p)
}

var _ pflag.Value = &enumValue[string]{}

func enumFlag[S ~string](fs *pflag.FlagSet, name string, value S, alts []S, usage string) *S {
	var p S
	fs.Var(newEnumValue(value, alts, &p), name, fmt.Sprintf("%s (one of %v)", usage, alts))
	return &p
}

func getEnumFlag[S ~string](fs *pflag.FlagSet, name string) (S, error) {
	f := fs.Lookup(name)
	if f == nil {
		return "", fmt.Errorf("%q not found from flags", name)
	}
	ev := f.Value.(*enumValue[S])
	if ev == nil || ev.p == nil {
		return "", nil
	}
	return *ev.p, nil
}
