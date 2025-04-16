// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

// Cell implements the processing of the CiliumLocalRedirectPolicy CRD.
// For each policy it creates a pseudo-service with suffix -local-redirect
// and associates to it all matching local pods as backends. The service
// frontends that are being redirected will then take the backends of the
// pseudo-service.
var Cell = cell.Module(
	"local-redirect-policies",
	"Controller for CiliumLocalRedirectPolicy",

	cell.Provide(
		// Provide Table[*LocalRedirectPolicy]. Used from replaceAPI.
		statedb.RWTable[*LocalRedirectPolicy].ToTable,

		// Provide the lrpIsEnabled value. Provided globally as it is
		// used by replaceAPI (DecorateAll runs in root scope).
		newLRPIsEnabled,

		// Provide the [lbmap.SkipLBMap]. Provided globally to register it.
		newSkipLBMap,

		// Provide the 'skiplbmap' command for inspecting SkipLBMap.
		newSkipLBMapCommand,
	),

	cell.ProvidePrivate(
		newLRPListerWatcher,
		NewLRPTable,
		newDesiredSkipLBTable,
	),

	cell.Invoke(
		// Reflect the CiliumLocalRedirectPolicy CRDs into Table[*LocalRedirectPolicy]
		registerLRPReflector,

		// Register a controller to process the changes in the LRP, pod and frontend
		// tables.
		registerLRPController,

		// Register the SkipLBMap recnociler and the endpoint subscriber for pulling
		// pod netns cookies
		registerSkipLBReconciler,
	),

	metrics.Metric(newControllerMetrics),

	// Replace the REST API implementation if enabled
	cell.DecorateAll(replaceAPI),
)

func replaceAPI(enabled lrpIsEnabled, old service.GetLrpHandler, db *statedb.DB, lrps statedb.Table[*LocalRedirectPolicy]) service.GetLrpHandler {
	if !enabled {
		return old
	}
	return &getLrpHandler{db, lrps}
}

type lrpIsEnabled bool

func newLRPIsEnabled(expConfig loadbalancer.Config, daemonConfig *option.DaemonConfig) lrpIsEnabled {
	return lrpIsEnabled(
		expConfig.EnableExperimentalLB && daemonConfig.EnableLocalRedirectPolicy,
	)
}

type controllerMetrics struct {
	ControllerDuration metric.Histogram
}

func newControllerMetrics() controllerMetrics {
	return controllerMetrics{
		ControllerDuration: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "localredirectpolicy",
			Name:      "controller_duration_seconds",
			Help:      "Histogram of LocalRedirectPolicy processing times",
			Disabled:  true,
			// Use buckets in the 0.5ms-1.0s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}),
	}
}
