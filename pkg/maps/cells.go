// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
)

// Cell contains all cells which are providing BPF Maps.
var Cell = cell.Module(
	"maps",
	"BPF Maps",

	// Provides the auth.Map which contains the authentication state between Cilium security identities.
	authmap.Cell,

	// ConfigMap stores runtime configuration state for the Cilium datapath.
	configmap.Cell,

	// Receives datapath signals for GC fill-up events
	// Note that we can't import this from ctmap package, as gc needs to import ctmap.
	gc.Cell,

	// Provides access to egressgateway specific maps.
	egressmap.Cell,

	// Provides signalmap for datapath signals
	signalmap.Cell,

	// Provides the node map which contains information about node IDs and their IP addresses.
	nodemap.Cell,
)
