// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import dump "github.com/cilium/cilium/bugtool/dump"

// getEnvoyDump returns task for dumping Envoy config from envoys
// local admin socket.
func getEnvoyDump() dump.Tasks {
	return []dump.Task{dump.NewRequest(
		"envoy-config",
		"http://admin/config_dump?include_eds",
	).WithUnixSocketExists("/var/run/cilium/envoy-admin.sock")}
}
