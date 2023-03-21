// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	dump "github.com/cilium/cilium/bugtool/dump"
)

func CiliumTasks() dump.Tasks {
	ts := dump.Tasks{}
	for _, cmd := range ciliumCommandsJSON() {
		ts = append(ts, createExecFromString(cmd, "json"))
	}
	return ts
}

func ciliumCommandsJSON() []string {
	var commands []string
	generators := []func() []string{
		CiliumAgentAPICLICommands,
	}

	for _, generator := range generators {
		commands = append(commands, generator()...)
	}

	return commands
}

// CiliumAgentAPICLICommands returns a list of all dump commands that use the
// Ciliums Agent CLI binary to dump data from the Agents API.
func CiliumAgentAPICLICommands() []string {
	commands := []string{
		"cilium debuginfo --output=json", // debuginfo uses different output flag format.
	}
	// TODO: Many of these are redundant with debuginfo, clean them up.
	for _, cmd := range []string{
		"cilium metrics list",
		"cilium fqdn cache list",
		"cilium config -a",
		"cilium encrypt status",
		"cilium endpoint list",
		"cilium bpf bandwidth list",
		"cilium bpf tunnel list",
		"cilium bpf lb list",
		"cilium bpf lb list --revnat",
		"cilium bpf lb list --frontends",
		"cilium bpf lb list --backends",
		"cilium bpf lb list --source-ranges",
		"cilium bpf lb maglev list",
		"cilium bpf egress list",
		"cilium bpf vtep list",
		"cilium bpf endpoint list",
		"cilium bpf ct list global",
		"cilium bpf nat list",
		"cilium bpf ipmasq list",
		"cilium bpf ipcache list",
		"cilium bpf policy get --all --numeric",
		"cilium bpf sha list",
		"cilium bpf fs show",
		"cilium bpf recorder list",
		"cilium ip list -n",
		"cilium map list",
		"cilium map events cilium_ipcache",
		"cilium map events cilium_tunnel_map",
		"cilium map events cilium_lb4_services_v2",
		"cilium map events cilium_lb4_backends_v2",
		"cilium map events cilium_lxc",
		"cilium service list",
		"cilium recorder list",
		"cilium status",
		"cilium identity list",
		"cilium-health status",
		"cilium policy get",
		"cilium policy selectors",
		"cilium node list",
		"cilium lrp list",
		"cilium cgroups list",
	} {
		commands = append(commands, cmd+" -o json")
	}
	return commands
}
