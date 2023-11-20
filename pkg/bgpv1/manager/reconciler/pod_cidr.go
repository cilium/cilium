// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type ExportPodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// exportPodCIDRReconciler is a ConfigReconciler which reconciles the
// advertisement of the private Kubernetes PodCIDR block.
type ExportPodCIDRReconciler struct{}

// ExportPodCIDRReconcilerMetadata keeps a list of all advertised Paths
type ExportPodCIDRReconcilerMetadata []*types.Path

func NewExportPodCIDRReconciler() ExportPodCIDRReconcilerOut {
	return ExportPodCIDRReconcilerOut{
		Reconciler: &ExportPodCIDRReconciler{},
	}
}

func (r *ExportPodCIDRReconciler) Name() string {
	return "ExportPodCIDR"
}

func (r *ExportPodCIDRReconciler) Priority() int {
	return 30
}

func (r *ExportPodCIDRReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if p.CurrentServer == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil ServerWithConfig")
	}
	if p.CiliumNode == nil {
		return fmt.Errorf("attempted pod CIDR advertisements reconciliation with nil local CiliumNode")
	}

	var toAdvertise []*types.Path
	for _, cidr := range p.CiliumNode.Spec.IPAM.PodCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse prefix %s: %w", cidr, err)
		}
		toAdvertise = append(toAdvertise, types.NewPathForPrefix(prefix))
	}

	advertisements, err := exportAdvertisementsReconciler(&advertisementsReconcilerParams{
		ctx:       ctx,
		name:      "pod CIDR",
		component: "exportPodCIDRReconciler",
		enabled:   *p.DesiredConfig.ExportPodCIDR,

		sc:   p.CurrentServer,
		newc: p.DesiredConfig,

		currentAdvertisements: r.getMetadata(p.CurrentServer),
		toAdvertise:           toAdvertise,
	})

	if err != nil {
		return err
	}

	// Update the server config's list of current advertisements only if the
	// reconciliation logic didn't return any error
	r.storeMetadata(p.CurrentServer, advertisements)
	return nil
}

func (r *ExportPodCIDRReconciler) getMetadata(sc *instance.ServerWithConfig) ExportPodCIDRReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(ExportPodCIDRReconcilerMetadata, 0)
	}
	return sc.ReconcilerMetadata[r.Name()].(ExportPodCIDRReconcilerMetadata)
}

func (r *ExportPodCIDRReconciler) storeMetadata(sc *instance.ServerWithConfig, meta ExportPodCIDRReconcilerMetadata) {
	sc.ReconcilerMetadata[r.Name()] = meta
}
