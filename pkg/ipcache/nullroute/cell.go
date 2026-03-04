// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nullroute

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"null-route-reconciler",
	"Null route reconciliation logic",

	cell.ProvidePrivate(newLoadBalancerFrontendWatcher),
	cell.Invoke(registerLoadBalancerFrontendWatcher),
)
