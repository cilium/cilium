// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	podIPPoolNameLabel      = "io.cilium.podippool.name"
	podIPPoolNamespaceLabel = "io.cilium.podippool.namespace"
)

type PodIPPoolReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type PodIPPoolReconciler struct {
	poolStore store.BGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]
}

// PodIPPoolReconcilerMetadata holds any announced pod ip pool CIDRs keyed by pool name of the backing CiliumPodIPPool.
type PodIPPoolReconcilerMetadata map[resource.Key][]*types.Path

func NewPodIPPoolReconciler(poolStore store.BGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]) PodIPPoolReconcilerOut {
	if poolStore == nil {
		return PodIPPoolReconcilerOut{}
	}

	return PodIPPoolReconcilerOut{
		Reconciler: &PodIPPoolReconciler{
			poolStore: poolStore,
		},
	}
}

func (r *PodIPPoolReconciler) Name() string {
	return "PodIPPool"
}

func (r *PodIPPoolReconciler) Priority() int {
	return 50
}

func (r *PodIPPoolReconciler) Init(_ *instance.ServerWithConfig) error {
	return nil
}

func (r *PodIPPoolReconciler) Cleanup(_ *instance.ServerWithConfig) {}

func (r *PodIPPoolReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	lp := r.populateLocalPools(p.CiliumNode)

	if err := r.fullReconciliation(ctx, p.CurrentServer, p.DesiredConfig, lp); err != nil {
		return fmt.Errorf("full reconciliation failed: %w", err)
	}

	return nil
}

func (r *PodIPPoolReconciler) getMetadata(sc *instance.ServerWithConfig) PodIPPoolReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(PodIPPoolReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(PodIPPoolReconcilerMetadata)
}

// populateLocalPools returns a map of allocated multi-pool IPAM CIDRs of the local CiliumNode,
// keyed by the pool name.
func (r *PodIPPoolReconciler) populateLocalPools(localNode *v2api.CiliumNode) map[string][]netip.Prefix {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "PodIPPoolReconciler",
			},
		)
	)

	if localNode == nil {
		return nil
	}

	lp := make(map[string][]netip.Prefix)
	for _, pool := range localNode.Spec.IPAM.Pools.Allocated {
		var prefixes []netip.Prefix
		for _, cidr := range pool.CIDRs {
			if p, err := cidr.ToPrefix(); err == nil {
				prefixes = append(prefixes, *p)
			} else {
				l.Errorf("invalid ipam pool cidr %v: %v", cidr, err)
			}
		}
		lp[pool.Pool] = prefixes
	}

	return lp
}

// fullReconciliation reconciles all pod ip pools.
func (r *PodIPPoolReconciler) fullReconciliation(ctx context.Context,
	sc *instance.ServerWithConfig,
	newc *v2alpha1api.CiliumBGPVirtualRouter,
	localPools map[string][]netip.Prefix) error {
	podIPPoolAnnouncements := r.getMetadata(sc)
	// Loop over all existing announcements, delete announcements for pod ip pools that no longer exist.
	for poolKey := range podIPPoolAnnouncements {
		_, found, err := r.poolStore.GetByKey(poolKey)
		if err != nil {
			return fmt.Errorf("failed to get pod ip pool from resource store: %w", err)
		}
		// If the pod ip pool no longer exists, withdraw all associated routes.
		if !found {
			if err := r.withdrawPool(ctx, sc, poolKey); err != nil {
				return fmt.Errorf("failed to withdraw pod ip pool: %w", err)
			}
			continue
		}
	}

	// Loop over all pod ip pools, reconcile any updates to the pool.
	pools, err := r.poolStore.List()
	if err != nil {
		return fmt.Errorf("failed to list ip pools from store: %w", err)
	}
	for _, pool := range pools {
		if err := r.reconcilePodIPPool(ctx, sc, newc, pool, localPools); err != nil {
			return fmt.Errorf("failed to reconcile pod ip pool: %w", err)
		}
	}

	return nil
}

// withdrawPool removes all announcements for the given pod ip pool.
func (r *PodIPPoolReconciler) withdrawPool(ctx context.Context, sc *instance.ServerWithConfig, key resource.Key) error {
	podIPPoolAnnouncements := r.getMetadata(sc)
	advertisements := podIPPoolAnnouncements[key]
	// Loop in reverse order so we can delete without effect to the iteration.
	for i := len(advertisements) - 1; i >= 0; i-- {
		advertisement := advertisements[i]
		if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: advertisement}); err != nil {
			// Persist remaining advertisements
			podIPPoolAnnouncements[key] = advertisements
			return fmt.Errorf("failed to withdraw deleted pod ip pool route: %v: %w", advertisement.NLRI, err)
		}

		// Delete the advertisement after each withdraw in case we error half way through
		advertisements = slices.Delete(advertisements, i, i+1)
	}

	// If all were withdrawn without error, we can delete the whole pod ip pool from the map
	delete(podIPPoolAnnouncements, key)

	return nil
}

// reconcilePodIPPool ensures the CIDRs of the given pool are announced if they are present
// on the local node, adding missing announcements or withdrawing unwanted ones.
func (r *PodIPPoolReconciler) reconcilePodIPPool(ctx context.Context,
	sc *instance.ServerWithConfig,
	newc *v2alpha1api.CiliumBGPVirtualRouter,
	pool *v2alpha1api.CiliumPodIPPool,
	localPools map[string][]netip.Prefix) error {
	podIPPoolAnnouncements := r.getMetadata(sc)
	poolKey := resource.NewKey(pool)

	desiredRoutes, err := r.poolDesiredRoutes(newc, pool, localPools)
	if err != nil {
		return fmt.Errorf("poolDesiredRoutes(): %w", err)
	}

	for _, desiredRoute := range desiredRoutes {
		// If this route has already been announced, don't add it again
		if slices.ContainsFunc(podIPPoolAnnouncements[poolKey], func(existing *types.Path) bool {
			return desiredRoute.String() == existing.NLRI.String()
		}) {
			continue
		}

		// Advertise the new cidr
		advertPathResp, err := sc.Server.AdvertisePath(ctx, types.PathRequest{
			Path: types.NewPathForPrefix(desiredRoute),
		})
		if err != nil {
			return fmt.Errorf("failed to advertise podippool cidr route %v: %w", desiredRoute, err)
		}
		podIPPoolAnnouncements[poolKey] = append(podIPPoolAnnouncements[poolKey], advertPathResp.Path)
	}

	// Loop over announcements in reverse order so we can delete entries without effecting iteration.
	for i := len(podIPPoolAnnouncements[poolKey]) - 1; i >= 0; i-- {
		announcement := podIPPoolAnnouncements[poolKey][i]
		// If the announcement is within the list of desired routes, don't remove it
		if slices.ContainsFunc(desiredRoutes, func(existing netip.Prefix) bool {
			return existing.String() == announcement.NLRI.String()
		}) {
			continue
		}

		if err := sc.Server.WithdrawPath(ctx, types.PathRequest{Path: announcement}); err != nil {
			return fmt.Errorf("failed to withdraw podippool cidr route %s: %w", announcement.NLRI, err)
		}

		// Delete announcement from slice
		podIPPoolAnnouncements[poolKey] = slices.Delete(podIPPoolAnnouncements[poolKey], i, i+1)
	}

	return nil
}

// poolDesiredRoutes returns routes that should be announced for the given pool.
func (r *PodIPPoolReconciler) poolDesiredRoutes(
	newc *v2alpha1api.CiliumBGPVirtualRouter,
	pool *v2alpha1api.CiliumPodIPPool,
	localPools map[string][]netip.Prefix) ([]netip.Prefix, error) {
	if newc.PodIPPoolSelector == nil {
		// If the vRouter has no pool selector, there are no desired routes.
		return nil, nil
	}

	// The vRouter has a pool selector, so determine the desired routes.
	poolSelector, err := slim_metav1.LabelSelectorAsSelector(newc.PodIPPoolSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to convert label selector: %w", err)
	}

	// Ignore non matching pools.
	if !poolSelector.Matches(podIPPoolLabelSet(pool)) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix
	if localCIDRs, ok := localPools[pool.Name]; ok {
		desiredRoutes = append(desiredRoutes, localCIDRs...)
	}

	return desiredRoutes, nil
}

func podIPPoolLabelSet(pool *v2alpha1api.CiliumPodIPPool) labels.Labels {
	poolLabels := maps.Clone(pool.Labels)
	if poolLabels == nil {
		poolLabels = make(map[string]string)
	}
	poolLabels[podIPPoolNameLabel] = pool.Name
	poolLabels[podIPPoolNamespaceLabel] = pool.Namespace
	return labels.Set(poolLabels)
}
