// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ReconcileParams struct {
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
	NewLBServiceReconciler,
	NewRoutePolicyReconciler,
)

// log is the logger used by the reconcilers
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
