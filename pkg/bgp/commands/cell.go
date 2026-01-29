// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/bgp/agent"
)

var Cell = cell.Provide(BGPCommands)

func BGPCommands(bgpMgr agent.BGPRouterManager) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"bgp/peers": BGPPPeersCmd(bgpMgr),
	})
}
