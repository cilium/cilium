// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
)

var (
	// Cell implements handling of the Cilium(Clusterwide)EnvoyConfig handling
	// and backend synchronization towards Envoy.
	Cell = cell.Module(
		"ciliumenvoyconfig",
		"CiliumEnvoyConfig handling",

		cell.Config(CECConfig{}),

		// Bridge the external dependencies to the internal APIs. In tests
		// mocks are used for these.
		cell.ProvidePrivate(
			newPolicyTrigger,
			func(xds envoy.XDSServer) resourceMutator { return xds },
		),

		cell.Provide(
			newCECResourceParser,
			newPortAllocator,
		),

		tableCells,
		controllerCells,
	)

	controllerCells = cell.Group(
		cell.Invoke(registerCECController),
		metrics.Metric(newMetrics),
	)

	tableCells = cell.Group(
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

func newPortAllocator(proxy *proxyports.ProxyPorts) PortAllocator {
	return proxy
}

type Metrics struct {
	ControllerDuration metric.Histogram
}

func newMetrics() Metrics {
	return Metrics{
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

type FeatureMetrics interface {
	AddCEC()
	DelCEC()
	AddCCEC()
	DelCCEC()
}
