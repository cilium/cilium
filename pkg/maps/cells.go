// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

// Cell contains all cells which are providing BPF Maps.
var Cell = cell.Module(
	"maps",
	"BPF Maps",

	// Provides the auth.Map which contains the authentication state between Cilium security identities.
	authmap.Cell,

	// ConfigMap stores runtime configuration state for the Cilium datapath.
	configmap.Cell,

	// Provides access to egressgateway specific maps.
	egressmap.Cell,
)
