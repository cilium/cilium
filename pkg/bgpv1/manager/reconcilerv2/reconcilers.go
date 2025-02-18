// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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
	DesiredConfig *v2.CiliumBGPNodeInstance
	CiliumNode    *v2.CiliumNode
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
func GetActiveReconcilers(log logrus.FieldLogger, reconcilers []ConfigReconciler) []ConfigReconciler {
	recMap := make(map[string]ConfigReconciler)
	for _, r := range reconcilers {
		if r == nil {
			continue // reconciler not initialized
		}
		if existing, exists := recMap[r.Name()]; exists {
			if existing.Priority() == r.Priority() {
				log.Warnf("Skipping duplicate BGP v2 reconciler %s with the same priority (%d)", existing.Name(), existing.Priority())
				continue
			}
			if existing.Priority() < r.Priority() {
				log.Debugf("Skipping BGP v2 reconciler %s (priority %d) as it has lower priority than the existing one (%d)",
					r.Name(), r.Priority(), existing.Priority())
				continue
			}
			log.Debugf("Overriding existing BGP v2 reconciler %s (priority %d) with higher priority one (%d)",
				existing.Name(), existing.Priority(), r.Priority())
		}
		recMap[r.Name()] = r
	}

	var activeReconcilers []ConfigReconciler
	for _, r := range recMap {
		log.Debugf("Adding BGP v2 reconciler: %v (priority %d)", r.Name(), r.Priority())
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
