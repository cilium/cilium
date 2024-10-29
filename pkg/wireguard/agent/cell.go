// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package agent

import (
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"wireguard",
	"Manages WireGuard",

	cell.Provide(NewAgent),
	cell.Invoke(registerNodeReconciler),
)

func registerNodeReconciler(
	agent *Agent,
	daemonConfig *option.DaemonConfig,
	recParams reconciler.Params,
	table statedb.RWTable[*node.TableNode],
) error {
	if !daemonConfig.EnableWireguard {
		return nil
	}
	ops := &nodeOps{agent}
	_, err := reconciler.Register(
		recParams,
		table,
		(*node.TableNode).Clone,
		func(n *node.TableNode, s reconciler.Status) *node.TableNode {
			n.Statuses = n.Statuses.Set("wireguard", s)
			return n
		},
		func(n *node.TableNode) reconciler.Status {
			return n.Statuses.Get("wireguard")
		},
		ops,
		nil,
	)
	return err
}
