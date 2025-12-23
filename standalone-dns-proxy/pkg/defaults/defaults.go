// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

const (
	// RuntimePath is the default path to the standalone DNS proxy runtime directory.
	// This is independent of Cilium's runtime directory to ensure SDP can start
	// regardless of Cilium's state.
	RuntimePath = "/var/run/standalone-dns-proxy"

	// ShellSockPath is the path to the UNIX domain socket exposing the debug shell
	ShellSockPath = RuntimePath + "/shell.sock"

	// HealthSockPath is the path to the UNIX domain socket for health checks.
	// This is used by the 'standalone-dns-proxy health' command for K8s probes.
	HealthSockPath = RuntimePath + "/health.sock"
)
