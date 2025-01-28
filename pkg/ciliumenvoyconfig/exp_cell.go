// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/envoy"
)

var (
	// experimentalCell implements handling of the Cilium(Clusterwide)EnvoyConfig handling
	// and backend synchronization towards Envoy against the experimental load-balancing
	// control-plane (pkg/loadbalancer/experimental). It is dormant unless 'enable-experimental-lb'
	// is set, in which case the other implementation is disabled and this is enabled.
	experimentalCell = cell.Module(
		"experimental",
		"CiliumEnvoyConfig integration with the experimental LB control-plane",

		// Bridge the external dependencies to the internal APIs. In tests
		// mocks are used for these.
		cell.ProvidePrivate(
			newPolicyTrigger,
			func(xds envoy.XDSServer) resourceMutator { return xds },
		),

		experimentalTableCells,
		experimentalControllerCells,
	)

	experimentalControllerCells = cell.Invoke(registerCECController)

	experimentalTableCells = cell.Group(
		cell.ProvidePrivate(
			NewCECTable,
			statedb.RWTable[*CEC].ToTable,
			NewEnvoyResourcesTable,
			newNodeLabels,
			cecListerWatchers,
		),
		cell.Invoke(
			registerCECReflector,
			registerEnvoyReconciler,
		),
	)
)
