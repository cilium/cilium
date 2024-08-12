// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/maps/act"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/maps/multicast"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/srv6map"
)

// Cell contains all cells which are providing BPF Maps.
var Cell = cell.Module(
	"maps",
	"BPF Maps",

	cell.Provide(newMapApiHandler),

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

	// Provides access to the L2 responder map.
	l2respondermap.Cell,

	// Provides access to the multicast maps.
	multicast.Cell,

	// Provides access to the SRv6 maps.
	srv6map.Cell,

	// Bandwidth (cilium_throttle) map contains the per-endpoint bandwidth limits.
	// Provides RWTable[bwmap.Edt] for configuring the limits.
	bwmap.Cell,

	// Provides access to ActiveConnectionTracking map.
	act.Cell,

	// Provides access to NAT maps.
	nat.Cell,
)

type mapApiHandlerOut struct {
	cell.Out

	GetMapHandler           daemonapi.GetMapHandler
	GetMapNameHandler       daemonapi.GetMapNameHandler
	GetMapNameEventsHandler daemonapi.GetMapNameEventsHandler
}

func newMapApiHandler(logger logrus.FieldLogger) mapApiHandlerOut {
	return mapApiHandlerOut{
		GetMapHandler:           &getMapHandler{},
		GetMapNameHandler:       &getMapNameHandler{},
		GetMapNameEventsHandler: &getMapNameEventsHandler{logger: logger, mapGetter: &mapGetterImpl{}},
	}
}
