// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	dump "github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/bugtool/options"
)

// CiliumAgentAPICLICommands returns a list of all dump commands that use the
// Ciliums Agent CLI binary to dump data from the Agents API.
func CiliumTasks(conf *options.Config) dump.Tasks {
	ts := dump.Tasks{
		createExecFromString("cilium debuginfo --output json", "json"),
	}
	if conf.HumanReadable {
		ts = append(ts, createExecFromString("cilium debuginfo", "md"))
	}

	// TODO: Many of these are redundant with debuginfo, clean them up.
	for _, cmd := range []string{
		"cilium metrics list",
		"cilium fqdn cache list",
		"cilium config -a",
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
	} {
		ts = append(ts, createExecFromString(cmd+" -o json", "json"))
		if conf.HumanReadable {
			ts = append(ts, createExecFromString(cmd, "md"))
		}
	}

	// Does not support json output.
	ts = append(ts, createExecFromString("cilium encrypt status", "md"))
	ts = append(ts, createExecFromString("cilium cgroups list", "md"))
	return ts
}
