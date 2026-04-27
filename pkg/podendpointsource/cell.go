// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package podendpointsource turns IPCache pod entries into local-cluster
// per-pod events with IPs, node IP, and identity labels.
package podendpointsource

import (
	"github.com/cilium/hive/cell"
)

// Cell provides a [Source] backed by IPCache.
var Cell = cell.Module(
	"pod-endpoint-source",
	"Observes pod endpoints from the IPCache and exposes them as a stream",

	cell.Provide(newSource),
)
