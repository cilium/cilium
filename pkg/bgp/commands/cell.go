// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/bgp/agent"
)

var Cell = cell.Provide(
	// Provide command map then provide it as a a script.CmdsOut. This
	// indirection gives us the ability to override the bgp/ commands with
	// DecorateAll. This is useful for switching to a different command
	// implementation with some custom logic.
	NewBGPCommands,
	func(cmds BGPCommands) hive.ScriptCmdsOut {
		return hive.NewScriptCmds(cmds)
	},
)

type BGPCommands map[string]script.Cmd

func NewBGPCommands(bgpMgr agent.BGPRouterManager) BGPCommands {
	return map[string]script.Cmd{
		"bgp/peers":  BGPPeersCmd(bgpMgr),
		"bgp/routes": BGPRoutesCmd(bgpMgr),
	}
}
