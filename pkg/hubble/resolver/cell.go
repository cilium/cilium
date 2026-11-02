// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the shared identity, endpoint, DNS and service getters, backed
// by the agent state.
var Cell = cell.Module(
	"hubble-resolver",
	"Provides shared identity endpoint DNS and service resolvers for Hubble",

	cell.Provide(
		NewIdentityGetter,
		NewEndpointGetter,
		NewDNSGetter,
		NewServiceGetter,
		NewIPGetter,
		NewPodMetadataGetter,
		NewLinkGetter,
	),
)
