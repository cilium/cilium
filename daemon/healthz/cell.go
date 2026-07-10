// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthz

import "github.com/cilium/hive/cell"

var Cell = cell.Group(
	// Agent Healthz
	agentHealthzCell,

	// KubeProxy Healthz
	kubeProxyHealthzCell,
)
