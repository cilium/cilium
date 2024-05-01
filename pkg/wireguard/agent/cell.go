// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package agent

import (
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"wireguard",
	"Manages WireGuard",

	cell.Provide(NewAgent),
	cell.ProvidePrivate(nodeReconcilerConfig),
	cell.Invoke(registerReconciler),
)

func registerReconciler(daemonConfig *option.DaemonConfig, recConfig reconciler.Config[node.Node], recParams reconciler.Params) error {
	if !daemonConfig.EnableWireguard {
		return nil
	}
	return reconciler.Register(recConfig, recParams)
}
