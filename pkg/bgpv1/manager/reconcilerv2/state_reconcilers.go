// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"log/slog"
	"sort"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

const (
	CRDStatusReconcilerName     = "CiliumBGPNodeConfigStatusReconciler"
	CRDStatusReconcilerPriority = 50
)

type StateReconcileParams struct {
	// ConfigMode is the current configuration mode of BGP control plane
	// This is required by some reconcilers to determine if they need to run or not.
	ConfigMode *mode.ConfigMode

	// UpdatedInstance is the BGP instance that is being updated.
	UpdatedInstance *instance.BGPInstance

	// DeletedInstance is the BGP instance that is already deleted.
	DeletedInstance string
}

type StateReconciler interface {
	Name() string
	Priority() int
	Reconcile(ctx context.Context, params StateReconcileParams) error
}

var StateReconcilers = cell.ProvidePrivate(
	NewStatusReconciler,
)

func GetActiveStateReconcilers(logger *slog.Logger, reconcilers []StateReconciler) []StateReconciler {
	recMap := make(map[string]StateReconciler)
	for _, r := range reconcilers {
		if r == nil {
			continue // reconciler not initialized
		}
		if existing, exists := recMap[r.Name()]; exists {
			if existing.Priority() == r.Priority() {
				logger.Warn(
					"Skipping duplicate reconciler with the same priority",
					types.ReconcilerLogField, existing.Name(),
					types.PriorityLogField, existing.Priority(),
				)
				continue
			}
			if existing.Priority() < r.Priority() {
				logger.Debug(
					"Skipping reconciler as it has lower priority than the existing one",
					types.ReconcilerLogField, r.Name(),
					types.PriorityLogField, r.Priority(),
					types.ExistingPriorityLogField, existing.Priority(),
				)
				continue
			}
			logger.Debug(
				"Overriding existing reconciler with a higher priority one",
				types.ReconcilerLogField, existing.Name(),
				types.ExistingPriorityLogField, existing.Priority(),
				types.PriorityLogField, r.Priority(),
			)
		}
		recMap[r.Name()] = r
	}

	var activeReconcilers []StateReconciler
	for _, r := range recMap {
		logger.Debug("Adding BGP v2 reconciler",
			types.ReconcilerLogField, r.Name(),
			types.PriorityLogField, r.Priority(),
		)
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}
