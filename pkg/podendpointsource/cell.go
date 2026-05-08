// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package podendpointsource observes pod endpoints via the IPCache and
// exposes them as a [stream.Observable] of per-pod [Event]s.
//
// The package centralises the filtering, identity resolution and backpressure
// concerns that were previously replicated in every consumer of pod endpoint
// data (CiliumEndpoint or CiliumEndpointSlice watchers). Consumers inject a
// [Source] and subscribe to [Source.Observe]; they receive a deduplicated
// per-pod view of local-cluster pod endpoints with their identity labels
// already resolved.
package podendpointsource

import (
	"github.com/cilium/hive/cell"
)

// Cell provides a [Source] of pod endpoint events backed by the IPCache.
//
// The cell registers an IPCache listener during the agent's OnStart hook,
// after the global identity cache has been synced, and runs a background
// consumer goroutine that turns IPCache notifications into deduplicated
// per-pod events.
var Cell = cell.Module(
	"pod-endpoint-source",
	"Observes pod endpoints from the IPCache and exposes them as a stream",

	cell.Provide(newSource),
)
