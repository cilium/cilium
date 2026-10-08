// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/ipam"
)

// Cell provides the agent-side Azure integration.
var Cell = cell.Module(
	"azure-agent",
	"Agent-side Azure integration",

	cell.Provide(newProvider),
)

func newProvider(params providerParams) ipam.CloudProviderOut {
	return ipam.CloudProviderOut{Provider: &provider{params: params}}
}
