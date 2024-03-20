// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	podIPPoolNameLabel      = "io.cilium.podippool.name"
	podIPPoolNamespaceLabel = "io.cilium.podippool.namespace"
)

type PodIPPoolReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type PodIPPoolReconcilerIn struct {
	cell.In

	Logger     logrus.FieldLogger
	PeerAdvert *CiliumPeerAdvertisement
	PoolStore  store.BGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]
}

type PodIPPoolReconciler struct {
	logger     logrus.FieldLogger
	peerAdvert *CiliumPeerAdvertisement
	poolStore  store.BGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]
}

// PodIPPoolReconcilerMetadata holds any announced pod ip pool CIDRs keyed by pool name of the backing CiliumPodIPPool.
type PodIPPoolReconcilerMetadata struct {
	AFPaths AFPathsMap
}

func NewPodIPPoolReconciler(in PodIPPoolReconcilerIn) PodIPPoolReconcilerOut {
	if in.PoolStore == nil {
		return PodIPPoolReconcilerOut{}
	}

	return PodIPPoolReconcilerOut{
		Reconciler: &PodIPPoolReconciler{
			logger:     in.Logger.WithField(types.ReconcilerLogField, "PodIPPool"),
			peerAdvert: in.PeerAdvert,
			poolStore:  in.PoolStore,
		},
	}
}

func (r *PodIPPoolReconciler) Name() string {
	return "PodIPPool"
}

func (r *PodIPPoolReconciler) Priority() int {
	return 50
}

func (r *PodIPPoolReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: PodIPPoolReconciler reconciler called with nil CiliumBGPNodeConfig")
	}

	if p.CiliumNode == nil {
		return fmt.Errorf("BUG: PodIPPoolReconciler reconciler called with nil CiliumNode")
	}

	lp := r.populateLocalPools(p.CiliumNode)

	desiredFamilyAdverts, err := r.getDesiredPathsPerFamily(p, lp)
	if err != nil {
		return err
	}

	// reconcile family advertisements
	updatedAFPaths, err := ReconcileAFPaths(&ReconcileAFPathsParams{
		Logger:       r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:          ctx,
		Instance:     p.BGPInstance,
		DesiredPaths: desiredFamilyAdverts,
		CurrentPaths: r.getMetadata(p.BGPInstance).AFPaths,
	})

	// We set the metadata even if there is an error to make sure metadata state matches underlying BGP instance state.
	r.setMetadata(p.BGPInstance, PodIPPoolReconcilerMetadata{AFPaths: updatedAFPaths})
	return err
}

// populateLocalPools returns a map of allocated multi-pool IPAM CIDRs of the local CiliumNode,
// keyed by the pool name.
func (r *PodIPPoolReconciler) populateLocalPools(localNode *v2api.CiliumNode) map[string][]netip.Prefix {
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
				r.logger.WithField(types.PrefixLogField, cidr).WithError(err).Error("invalid IPAM pool CIDR")
			}
		}
		lp[pool.Pool] = prefixes
	}

	return lp
}

func (r *PodIPPoolReconciler) getDesiredPathsPerFamily(p ReconcileParams, lp map[string][]netip.Prefix) (AFPathsMap, error) {
	// get per peer per family pod cidr advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2alpha1api.BGPCiliumPodIPPoolAdvert)
	if err != nil {
		return nil, err
	}

	// list of configured pools
	configuredPools, err := r.poolStore.List()
	if err != nil {
		if errors.Is(err, store.ErrStoreUninitialized) {
			r.logger.Error("BUG: CiliumPodIPPool store is not initialized")
		}
		return nil, err
	}

	// Calculate desired paths per address family, collapsing per-peer advertisements into per-family advertisements.
	desiredFamilyAdverts := make(AFPathsMap)
	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			pathsPerFamily, exists := desiredFamilyAdverts[agentFamily]
			if !exists {
				pathsPerFamily = make(PathMap)
				desiredFamilyAdverts[agentFamily] = pathsPerFamily
			}

			for _, advert := range familyAdverts {
				// sanity check advertisement type
				if advert.AdvertisementType != v2alpha1api.BGPCiliumPodIPPoolAdvert {
					r.logger.WithField(types.AdvertTypeLogField, advert.AdvertisementType).Error("BUG: unexpected advertisement type")
					continue
				}

				desiredPaths, err := getDesiredPoolPaths(agentFamily, configuredPools, advert, lp)
				if err != nil {
					return nil, err
				}

				for _, path := range desiredPaths {
					// Note : we add pool prefix to the desiredPaths map for each peer. We could optimize this by storing
					// already evaluated pools per family in a map and skipping them if they are already evaluated.
					pathsPerFamily[path.NLRI.String()] = path
				}
			}
		}
	}

	return desiredFamilyAdverts, nil
}

func getDesiredPoolPaths(family types.Family, pools []*v2alpha1api.CiliumPodIPPool, advert v2alpha1api.BGPAdvertisement, lp map[string][]netip.Prefix) ([]*types.Path, error) {
	var desiredPaths []*types.Path
	for _, pool := range pools {
		// check if the pool selector matches the advertisement
		poolSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
		if err != nil {
			return nil, fmt.Errorf("failed to convert label selector: %w", err)
		}

		// Ignore non matching pool.
		if !poolSelector.Matches(podIPPoolLabelSet(pool)) {
			continue
		}

		if prefixes, exists := lp[pool.Name]; exists {
			// on the local node we have this pool configured.
			// add the prefixes to the desiredPaths.
			for _, prefix := range prefixes {
				path := types.NewPathForPrefix(prefix)
				path.Family = family

				// we only add path corresponding to the family of the prefix.
				if family.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
					desiredPaths = append(desiredPaths, path)
				}
				if family.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
					desiredPaths = append(desiredPaths, path)
				}
			}
		}
	}
	return desiredPaths, nil
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

func (r *PodIPPoolReconciler) getMetadata(i *instance.BGPInstance) PodIPPoolReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = PodIPPoolReconcilerMetadata{
			AFPaths: make(AFPathsMap),
		}
	}
	return i.Metadata[r.Name()].(PodIPPoolReconcilerMetadata)
}

func (r *PodIPPoolReconciler) setMetadata(i *instance.BGPInstance, metadata PodIPPoolReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}
