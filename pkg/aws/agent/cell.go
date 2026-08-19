// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/ipam"
)

// Cell provides the agent-side AWS integration. It is the home of everything
// AWS-specific the agent needs, currently the ENI customization of the
// multi-pool IPAM allocator.
//
// Registering it is unconditional: the parts it contributes declare what they
// handle (the IPAM provider declares its IPAM mode) and are only selected when
// the agent is configured accordingly.
var Cell = cell.Module(
	"aws-agent",
	"Agent-side AWS integration",

	cell.Provide(newProvider),
)

// newProvider is deliberately free of side effects: it runs in every agent,
// whatever the configured IPAM mode, and the provider only does work once the
// generic allocator calls Initialize. In particular, the IMDS is only queried
// from Initialize, and no observer is registered before then.
func newProvider(params providerParams) ipam.CloudProviderOut {
	return ipam.CloudProviderOut{Provider: &provider{params: params}}
}
