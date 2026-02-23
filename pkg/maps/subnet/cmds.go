// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
)

type scriptCommandsParams struct {
	cell.In

	SubnetMap subnetMap
}

func scriptCommands(p scriptCommandsParams) hive.ScriptCmdsOut {
	cmds := map[string]script.Cmd{
		"subnet/map-dump": subnetMapDumpCommand(p.SubnetMap),
	}

	return hive.NewScriptCmds(cmds)
}

func subnetMapDumpCommand(m subnetMap) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the subnet BPF map",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the subnet BPF map either to stdout or to a file.",
				"Each BPF map key-value is shown as one line, e.g.:",
				"PREFIX=10.0.0.1/24 IDENTITY=1234",
				"This command is for testing and debugging purposes only.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				out := dumpSubnetMap(m)
				if len(args) == 1 {
					err = os.WriteFile(s.Path(args[0]), []byte(out), 0644)
				} else {
					stdout = out
				}
				return
			}, nil
		},
	)
}

func dumpSubnetMap(m subnetMap) string {
	// Iterate through all map entries.
	data := make(map[string][]string)
	m.Map.DumpIfExists(data)

	// Sort by IP prefix for stable output.
	keys := slices.Sorted(maps.Keys(data))

	var result strings.Builder
	for _, k := range keys {
		result.WriteString(fmt.Sprintf("PREFIX=%s IDENTITY=%s\n", k, data[k][0]))
	}
	return result.String()
}
