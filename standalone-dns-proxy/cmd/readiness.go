// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
)

// ReadinessCell provides readiness check commands for the shell
var ReadinessCell = cell.Module(
	"readiness",
	"Readiness check commands for the standalone DNS proxy",
	cell.Provide(
		readinessCommands,
	),
)

// readinessCommands returns script commands for readiness checking.
func readinessCommands(provider ReadinessStatusProvider) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"readiness-check": readinessCheckCommand(provider),
	})
}

func readinessCheckCommand(provider ReadinessStatusProvider) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Check readiness status of standalone DNS proxy",
			Args:    "",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout, stderr string, err error) {
				// Check if the proxy is ready
				if !provider.IsReady() {
					return "", "", fmt.Errorf("standalone DNS proxy is not ready or not started")
				}
				return "OK\n", "", nil
			}, nil
		},
	)
}
