// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package components

import (
	"os"
	"strings"
)

const (
	// CiliumAgentName is the name of cilium-agent (daemon) process name.
	CiliumAgentName = "cilium-agent"
	// CiliumOperatortName is the name of cilium-operator process name.
	CiliumOperatortName = "cilium-operator"
	// CiliumDaemonTestName is the name of test binary for daemon package.
	CiliumDaemonTestName = "cmd.test"
)

// IsCiliumAgent checks whether the current process is cilium-agent (daemon).
func IsCiliumAgent() bool {
	binaryName := os.Args[0]
	return strings.HasSuffix(binaryName, CiliumAgentName) ||
		strings.HasSuffix(binaryName, CiliumDaemonTestName)
}
