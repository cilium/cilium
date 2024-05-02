// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"

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

// PoolAFPathsMap holds the desired paths per address family keyed by the pool name of the backing CiliumPodIPPool.
type PoolAFPathsMap map[resource.Key]AFPathsMap

// PodIPPoolReconcilerMetadata holds any announced pod ip pool CIDRs keyed by pool name of the backing CiliumPodIPPool.
type PodIPPoolReconcilerMetadata struct {
	PoolAFPaths PoolAFPathsMap
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

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2alpha1api.BGPCiliumPodIPPoolAdvert)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, p, desiredPeerAdverts, lp)
}

func (r *PodIPPoolReconciler) reconcilePaths(ctx context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, lp map[string][]netip.Prefix) error {
	poolsAFPaths, err := r.getDesiredPoolAFPaths(p, desiredPeerAdverts, lp)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(p.BGPInstance)
	for poolKey, desiredPoolAFPaths := range poolsAFPaths {
		currentPoolAFPaths, exists := metadata.PoolAFPaths[poolKey]
		if !exists && len(desiredPoolAFPaths) == 0 {
			// No paths to reconcile for this pool.
			continue
		}

		updatedPoolAFPaths, rErr := ReconcileAFPaths(&ReconcileAFPathsParams{
			Logger: r.logger.WithFields(
				logrus.Fields{
					types.InstanceLogField:  p.DesiredConfig.Name,
					types.PodIPPoolLogField: poolKey,
				}),
			Ctx:          ctx,
			Instance:     p.BGPInstance,
			DesiredPaths: desiredPoolAFPaths,
			CurrentPaths: currentPoolAFPaths,
		})

		if rErr == nil && len(desiredPoolAFPaths) == 0 {
			// No paths left for this pool.
			delete(metadata.PoolAFPaths, poolKey)
		} else {
			metadata.PoolAFPaths[poolKey] = updatedPoolAFPaths
		}
		err = errors.Join(err, rErr)
	}
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *PodIPPoolReconciler) getDesiredPoolAFPaths(p ReconcileParams, desiredFamilyAdverts PeerAdvertisements, lp map[string][]netip.Prefix) (PoolAFPathsMap, error) {
	desiredPoolAFPaths := make(PoolAFPathsMap)

	metadata := r.getMetadata(p.BGPInstance)

	// check if any pool is deleted
	for poolKey := range metadata.PoolAFPaths {
		_, exists, err := r.poolStore.GetByKey(poolKey)
		if err != nil {
			return nil, err
		}

		if !exists {
			// pool is deleted, mark it for removal
			desiredPoolAFPaths[poolKey] = nil
		}
	}

	pools, err := r.poolStore.List()
	if err != nil {
		return nil, err
	}

	for _, pool := range pools {
		desiredPaths, err := r.getDesiredAFPaths(pool, desiredFamilyAdverts, lp)
		if err != nil {
			return nil, err
		}

		poolKey := resource.Key{
			Name:      pool.Name,
			Namespace: pool.Namespace,
		}

		desiredPoolAFPaths[poolKey] = desiredPaths
	}
	return desiredPoolAFPaths, nil
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

func (r *PodIPPoolReconciler) getDesiredAFPaths(pool *v2alpha1api.CiliumPodIPPool, desiredPeerAdverts PeerAdvertisements, lp map[string][]netip.Prefix) (AFPathsMap, error) {
	// Calculate desired paths per address family, collapsing per-peer advertisements into per-family advertisements.
	desiredFamilyAdverts := make(AFPathsMap)

	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// sanity check advertisement type
				if advert.AdvertisementType != v2alpha1api.BGPCiliumPodIPPoolAdvert {
					r.logger.WithField(types.AdvertTypeLogField, advert.AdvertisementType).Error("BUG: unexpected advertisement type")
					continue
				}

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
						path.Family = agentFamily

						// we only add path corresponding to the family of the prefix.
						if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
							addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
						}
						if agentFamily.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
							addPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path)
						}
					}
				}
			}
		}
	}

	return desiredFamilyAdverts, nil
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
			PoolAFPaths: make(PoolAFPathsMap),
		}
	}
	return i.Metadata[r.Name()].(PodIPPoolReconcilerMetadata)
}

func (r *PodIPPoolReconciler) setMetadata(i *instance.BGPInstance, metadata PodIPPoolReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}
