// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/option"
)

type ExportPodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// exportPodCIDRReconciler is a ConfigReconciler which reconciles the
// advertisement of the private Kubernetes PodCIDR block.
type ExportPodCIDRReconciler struct {
	Logger *slog.Logger
}

// ExportPodCIDRReconcilerMetadata keeps a list of all advertised Paths
type ExportPodCIDRReconcilerMetadata []*types.Path

func NewExportPodCIDRReconciler(logger *slog.Logger, dc *option.DaemonConfig) ExportPodCIDRReconcilerOut {
	// Don't provide the reconciler if the IPAM mode is not supported
	if !types.CanAdvertisePodCIDR(dc.IPAMMode()) {
		logger.Info("Unsupported IPAM mode, disabling PodCIDR advertisements. exportPodCIDR doesn't take effect.")
		return ExportPodCIDRReconcilerOut{}
	}

	return ExportPodCIDRReconcilerOut{
		Reconciler: &ExportPodCIDRReconciler{Logger: logger},
	}
}

func (r *ExportPodCIDRReconciler) Name() string {
	return "ExportPodCIDR"
}

func (r *ExportPodCIDRReconciler) Priority() int {
	return 30
}

func (r *ExportPodCIDRReconciler) Init(_ *instance.ServerWithConfig) error {
	return nil
}

func (r *ExportPodCIDRReconciler) Cleanup(_ *instance.ServerWithConfig) {}

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
		logger:    r.Logger,
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
