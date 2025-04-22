// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var (
	// experimentalCell implements handling of the Cilium(Clusterwide)EnvoyConfig handling
	// and backend synchronization towards Envoy against the experimental load-balancing
	// control-plane (pkg/loadbalancer/experimental). It is dormant unless 'enable-experimental-lb'
	// is set, in which case the other implementation is disabled and this is enabled.
	Cell = cell.Module(
		"ciliumenvoycnofig",
		"CiliumEnvoyConfig handling",

		cell.Config(CECConfig{}),

		// Bridge the external dependencies to the internal APIs. In tests
		// mocks are used for these.
		cell.ProvidePrivate(
			newPolicyTrigger,
			func(xds envoy.XDSServer) resourceMutator { return xds },
		),

		cell.Provide(newCECResourceParser),

		experimentalTableCells,
		experimentalControllerCells,
	)

	experimentalControllerCells = cell.Group(
		cell.Invoke(registerCECController),
		metrics.Metric(newExperimentalMetrics),
	)

	experimentalTableCells = cell.Group(
		cell.ProvidePrivate(
			NewCECTable,
			statedb.RWTable[*CEC].ToTable,
			NewEnvoyResourcesTable,
			newNodeLabels,
			cecListerWatchers,
		),
		cell.Invoke(
			registerCECK8sReflector,
			registerEnvoyReconciler,
		),
	)
)

type experimentalMetrics struct {
	ControllerDuration metric.Histogram
}

func newExperimentalMetrics() experimentalMetrics {
	return experimentalMetrics{
		ControllerDuration: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "ciliumenvoyconfig",
			Name:      "controller_duration_seconds",
			Help:      "Histogram of CiliumEnvoyConfig processing times",
			Disabled:  true,
			// Use buckets in the 0.5ms-1.0s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}),
	}
}

type CECMetrics interface {
	AddCEC()
	DelCEC()
	AddCCEC()
	DelCCEC()
}
