// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
)

// HealthCell provides health check commands for the shell
var HealthCell = cell.Module(
	"health",
	"Health check commands for the standalone DNS proxy",
	cell.Provide(
		healthCommands,
	),
)

// healthCommands returns script commands for health checking.
func healthCommands(provider HealthStatusProvider) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"health-check": healthCheckCommand(provider),
	})
}

func healthCheckCommand(provider HealthStatusProvider) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Check health status of standalone DNS proxy",
			Args:    "",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout, stderr string, err error) {
				// Check if the proxy is healthy
				if !provider.IsHealthy() {
					return "", "", fmt.Errorf("standalone DNS proxy is not healthy or not started")
				}
				return "OK\n", "", nil
			}, nil
		},
	)
}
