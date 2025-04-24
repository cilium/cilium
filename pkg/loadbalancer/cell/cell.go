// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/healthserver"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/redirectpolicy"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
)

// Load-balancing control-plane meta cell.
var Cell = cell.Group(
	// Provides [loadbalancer.Config] and [loadbalancer.ExternalConfig].
	loadbalancer.ConfigCell,

	// Load-balancing tables and the [writer.Writer] API
	writer.Cell,

	// Reflectors from external state to load-balancing tables
	reflectors.Cell,

	// LBMap wrapper around BPF maps
	maps.Cell,

	// Reconciliation from tables to BPF maps.
	reconciler.Cell,

	// Control-plane for CiliumLocalRedirectPolicy
	redirectpolicy.Cell,

	// Support for HealthCheckNodePort
	healthserver.Cell,

	cell.Module(
		"loadbalancing-adapters",
		"Adapters to legacy APIs",

		// Replace the [k8s.ServiceCacheReader] and [service.ServiceReader] if this
		// implementation is enabled.
		cell.Provide(newAdapters),
		cell.DecorateAll(decorateAdapters),
	),
)
