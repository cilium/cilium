// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"
	"sort"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/hive/cell"
)

type ReconcileParams struct {
	Logger        logging.FieldLogger
	CurrentServer *instance.ServerWithConfig
	DesiredConfig *v2alpha1api.CiliumBGPVirtualRouter
	CiliumNode    *v2api.CiliumNode
}

// ConfigReconciler is a interface for reconciling a particular aspect
// of an old and new *v2alpha1api.CiliumBGPVirtualRouter
type ConfigReconciler interface {
	// Name returns the name of a reconciler.
	Name() string
	// Priority is used to determine the order in which reconcilers are called. Reconcilers are called from lowest to
	// highest.
	Priority() int
	// Init is called upon virtual router instance creation. Reconcilers can initialize any instance-specific
	// resources here, and clean them up upon Cleanup call.
	Init(sc *instance.ServerWithConfig) error
	// Cleanup is called upon virtual router instance deletion. When called, reconcilers are supposed
	// to clean up all instance-specific resources saved outside the ReconcilerMetadata.
	Cleanup(sc *instance.ServerWithConfig)
	// Reconcile If the `Config` field in `params.sc` is nil the reconciler should unconditionally
	// perform the reconciliation actions, as no previous configuration is present.
	Reconcile(ctx context.Context, params ReconcileParams) error
}

// ConfigReconcilers contains all reconcilers used by the route manager to manage the BGP config.
var ConfigReconcilers = cell.Provide(
	NewPreflightReconciler,
	NewNeighborReconciler,
	NewExportPodCIDRReconciler,
	NewPodIPPoolReconciler,
	NewServiceReconciler,
	NewRoutePolicyReconciler,
)

func GetActiveReconcilers(logger logging.FieldLogger, reconcilers []ConfigReconciler) []ConfigReconciler {
	recMap := make(map[string]ConfigReconciler)
	for _, r := range reconcilers {
		if r == nil {
			continue // reconciler not initialized
		}
		if existing, exists := recMap[r.Name()]; exists {
			if existing.Priority() == r.Priority() {
				logger.Warn("Skipping duplicate BGP v1 reconciler with the same priority", slog.String("reconciler", existing.Name()), slog.Int("priority", existing.Priority()))
				continue
			}
			if existing.Priority() < r.Priority() {
				logger.Debug(
					"Skipping BGP v1 reconcileras it has lower priority than the existing one",
					slog.String("reconciler", r.Name()),
					slog.Int("priority", r.Priority()),
					slog.Int("existing-priority", existing.Priority()),
				)
				continue
			}
			logger.Debug(
				"Overriding existing BGP v1 reconciler with a higher priority one",
				slog.String("reconciler", existing.Name()),
				slog.Int("priority", existing.Priority()),
				slog.Int("existing-priority", r.Priority()),
			)
		}
		recMap[r.Name()] = r
	}

	var activeReconcilers []ConfigReconciler
	for _, r := range recMap {
		logger.Debug("Adding BGP v1 reconciler", slog.String("name", r.Name()), slog.Int("priority", r.Priority()))
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}
