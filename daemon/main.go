// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"path"

	dbgCmd "github.com/cilium/cilium/cilium-dbg/cmd"
	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	switch path.Base(os.Args[0]) {
	case "cilium":
		fallthrough
	case "cilium-dbg":
		dbgCmd.Execute()
	default:
		agentHive := hive.New(cmd.Agent)
		cmd.Execute(cmd.NewAgentCmd(agentHive))
	}
}
