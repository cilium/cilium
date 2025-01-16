// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"log/slog"
	"sort"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
)

const (
	NeighborReconcilerName  = "Neighbor"
	PodIPPoolReconcilerName = "PodIPPool"
	ServiceReconcilerName   = "Service"
	PodCIDRReconcilerName   = "PodCIDR"
)

// Reconciler Priorities, lower number means higher priority. It is used to determine the
// order in which reconcilers are called. Reconcilers are called from lowest to highest on
// each Reconcile event.
const (
	NeighborReconcilerPriority  = 60
	PodIPPoolReconcilerPriority = 50
	ServiceReconcilerPriority   = 40
	PodCIDRReconcilerPriority   = 30
)

var (
	// ErrAbortReconcile is used to indicate that the current reconcile loop should
	// be aborted.
	ErrAbortReconcile = errors.New("abort reconcile error")
)

type ReconcileParams struct {
	BGPInstance   *instance.BGPInstance
	DesiredConfig *v2alpha1.CiliumBGPNodeInstance
	CiliumNode    *v2api.CiliumNode
}

type ConfigReconciler interface {
	// Name returns the name of a reconciler.
	Name() string
	// Priority is used to determine the order in which reconcilers are called. Reconcilers are called from lowest to
	// highest.
	Priority() int
	// Init is called upon virtual router instance creation. Reconcilers can initialize any instance-specific
	// resources here, and clean them up upon Cleanup call.
	Init(i *instance.BGPInstance) error
	// Cleanup is called upon virtual router instance deletion. When called, reconcilers are supposed
	// to clean up all instance-specific resources saved outside the instance Metadata.
	Cleanup(i *instance.BGPInstance)
	// Reconcile performs the reconciliation actions for given BGPInstance.
	Reconcile(ctx context.Context, params ReconcileParams) error
}

var ConfigReconcilers = cell.Provide(
	NewNeighborReconciler,
	NewPodCIDRReconciler,
	NewPodIPPoolReconciler,
	NewServiceReconciler,
)

// GetActiveReconcilers returns a list of reconcilers in order of priority that should be used to reconcile the BGP config.
func GetActiveReconcilers(log logging.FieldLogger, reconcilers []ConfigReconciler) []ConfigReconciler {
	recMap := make(map[string]ConfigReconciler)
	for _, r := range reconcilers {
		if r == nil {
			continue // reconciler not initialized
		}
		if existing, exists := recMap[r.Name()]; exists {
			if existing.Priority() == r.Priority() {
				log.Warn(
					"Skipping duplicate BGP v2 reconciler with the same priority",
					slog.String("reconciler", existing.Name()),
					slog.Int("priority", existing.Priority()),
				)
				continue
			}
			if existing.Priority() < r.Priority() {
				log.Debug(
					"Skipping BGP v2 reconciler as it has lower priority than the existing one",
					slog.String("reconciler", r.Name()),
					slog.Int("priority", r.Priority()),
					slog.Int("existing-priority", existing.Priority()),
				)
				continue
			}
			log.Debug(
				"Overriding existing BGP v2 reconciler with a higher priority one",
				slog.String("reconciler", existing.Name()),
				slog.Int("existing-priority", existing.Priority()),
				slog.Int("priority", r.Priority()),
			)
		}
		recMap[r.Name()] = r
	}

	var activeReconcilers []ConfigReconciler
	for _, r := range recMap {
		log.Debug("Adding BGP v2 reconciler",
			slog.String("reconciler", r.Name()),
			slog.Int("priority", r.Priority()),
		)
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}

func (p ReconcileParams) ValidateParams() error {
	if p.DesiredConfig == nil {
		return errors.Join(errors.New("BUG: reconciler called with nil CiliumBGPNodeConfig"), ErrAbortReconcile)
	}
	if p.CiliumNode == nil {
		return errors.Join(errors.New("BUG: reconciler called with nil CiliumNode"), ErrAbortReconcile)
	}
	return nil
}
