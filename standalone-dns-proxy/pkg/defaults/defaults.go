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
)
