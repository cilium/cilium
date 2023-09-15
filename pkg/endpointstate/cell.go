// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointstate

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"endpoint-state-restore",
	"Restore the endpoints from previous run",

	cell.Provide(newRestorer),
)
