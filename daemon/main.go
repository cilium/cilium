// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	agentHive := hive.New(cmd.Agent)

	cmd.Execute(cmd.NewAgentCmd(agentHive))
}
