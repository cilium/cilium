// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"github.com/cilium/hive/cell"

	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/option"
)

// The top-level Hubble cell, implements several Hubble subsystems: reports pod
// network drops to k8s, Hubble flows based prometheus metrics, flows logging
// and export, and a couple of local and tcp gRPC servers.
var Cell = cell.Module(
	"hubble",
	"Exposes the Observer gRPC API and Hubble metrics",

	cell.Provide(newHubble),
)

type hubbleParams struct {
	cell.In

	AgentConfig       *option.DaemonConfig
	IdentityAllocator identitycell.CachingIdentityAllocator
}

func newHubble(params hubbleParams) *Hubble {
	return new(
		params.AgentConfig,
		params.IdentityAllocator,
	)
}
