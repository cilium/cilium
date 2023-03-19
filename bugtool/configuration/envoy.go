// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import dump "github.com/cilium/cilium/bugtool/dump"

const envoyUnixSock = "/var/run/cilium/envoy-admin.sock"

// getEnvoyDump returns task for dumping Envoy config from envoys
// local admin socket.
func getEnvoyDump() dump.Tasks {
	return []dump.Task{
		dump.NewRequest(
			"envoy-config",
			"http://admin/config_dump?include_eds",
		).WithUnixSocketExists(envoyUnixSock),
		dump.NewRequest(
			"envoy-metrics",
			"https://admin/stats/prometheus",
		).WithUnixSocketExists(envoyUnixSock),
	}
}
