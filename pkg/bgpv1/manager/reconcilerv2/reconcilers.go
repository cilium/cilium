// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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

var ConfigReconcilers = cell.ProvidePrivate(
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
				log.Warnf("Skipping duplicate reconciler %s with the same priority (%d)", existing.Name(), existing.Priority())
				continue
			}
			if existing.Priority() < r.Priority() {
				log.Debugf("Skipping reconciler %s (priority %d) as it has lower priority than the existing one (%d)",
					r.Name(), r.Priority(), existing.Priority())
				continue
			}
			log.Debugf("Overriding existing reconciler %s (priority %d) with higher priority one (%d)",
				existing.Name(), existing.Priority(), r.Priority())
		}
		recMap[r.Name()] = r
	}

	var activeReconcilers []ConfigReconciler
	for _, r := range recMap {
		log.Debugf("Adding BGP reconciler: %v (priority %d)", r.Name(), r.Priority())
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}
