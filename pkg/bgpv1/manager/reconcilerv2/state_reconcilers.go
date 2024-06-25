// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"sort"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
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

var StateReconcilers = cell.ProvidePrivate()

func GetActiveStateReconcilers(log logrus.FieldLogger, reconcilers []StateReconciler) []StateReconciler {
	recMap := make(map[string]StateReconciler)
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

	var activeReconcilers []StateReconciler
	for _, r := range recMap {
		log.Debugf("Adding BGP state reconciler: %v (priority %d)", r.Name(), r.Priority())
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return activeReconcilers
}
