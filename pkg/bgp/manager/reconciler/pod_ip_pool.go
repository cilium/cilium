// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	podIPPoolNameLabel      = "io.cilium.podippool.name"
	podIPPoolNamespaceLabel = "io.cilium.podippool.namespace"
)

type PodIPPoolReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type PodIPPoolReconcilerIn struct {
	cell.In

	Logger     *slog.Logger
	PeerAdvert *CiliumPeerAdvertisement
	PoolStore  store.BGPCPResourceStore[*v2alpha1.CiliumPodIPPool]

	DB                      *statedb.DB
	DesiredRoutePolicyTable statedb.RWTable[*bgpTables.DesiredRoutePolicy]
}

type PodIPPoolReconciler struct {
	logger                  *slog.Logger
	peerAdvert              *CiliumPeerAdvertisement
	poolStore               store.BGPCPResourceStore[*v2alpha1.CiliumPodIPPool]
	db                      *statedb.DB
	desiredRoutePolicyTable statedb.RWTable[*bgpTables.DesiredRoutePolicy]
	metadata                map[string]PodIPPoolReconcilerMetadata
}

// PodIPPoolReconcilerMetadata holds any announced pod ip pool CIDRs keyed by pool name of the backing CiliumPodIPPool.
type PodIPPoolReconcilerMetadata struct {
	PoolAFPaths ResourceAFPathsMap
}

func NewPodIPPoolReconciler(in PodIPPoolReconcilerIn) PodIPPoolReconcilerOut {
	if in.PoolStore == nil {
		return PodIPPoolReconcilerOut{}
	}

	return PodIPPoolReconcilerOut{
		Reconciler: &PodIPPoolReconciler{
			logger:                  in.Logger.With(types.ReconcilerLogField, "PodIPPool"),
			peerAdvert:              in.PeerAdvert,
			poolStore:               in.PoolStore,
			db:                      in.DB,
			desiredRoutePolicyTable: in.DesiredRoutePolicyTable,
			metadata:                make(map[string]PodIPPoolReconcilerMetadata),
		},
	}
}

func (r *PodIPPoolReconciler) Name() string {
	return PodIPPoolReconcilerName
}

func (r *PodIPPoolReconciler) Priority() int {
	return PodIPPoolReconcilerPriority
}

func (r *PodIPPoolReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = PodIPPoolReconcilerMetadata{
		PoolAFPaths: make(ResourceAFPathsMap),
	}
	return nil
}

func (r *PodIPPoolReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		if err := cleanupDesiredRoutePolicyStatements(r.db, r.desiredRoutePolicyTable, i.Name, r.Name()); err != nil {
			r.logger.Warn("Failed to clean up desired route policies",
				logfields.Error, err,
				types.InstanceLogField, i.Name,
				logfields.Owner, r.Name(),
			)
		}
		delete(r.metadata, i.Name)
	}
}

func (r *PodIPPoolReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	lp := r.populateLocalPools(p.CiliumNode)

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2.BGPCiliumPodIPPoolAdvert)
	if err != nil {
		return err
	}

	err = r.reconcileRoutePolicies(ctx, p, desiredPeerAdverts, lp)
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

	metadata.PoolAFPaths, err = ReconcileResourceAFPaths(ReconcileResourceAFPathsParams{
		Logger:                 r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:                    ctx,
		Router:                 p.BGPInstance.Router,
		DesiredResourceAFPaths: poolsAFPaths,
		CurrentResourceAFPaths: metadata.PoolAFPaths,
	})

	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *PodIPPoolReconciler) getDesiredPoolAFPaths(p ReconcileParams, desiredFamilyAdverts PeerAdvertisements, lp map[string][]netip.Prefix) (ResourceAFPathsMap, error) {
	desiredPoolAFPaths := make(ResourceAFPathsMap)

	metadata := r.getMetadata(p.BGPInstance)

	// check if any pool is deleted
	for poolKey := range metadata.PoolAFPaths {
		_, exists, err := r.poolStore.GetByKey(poolKey)
		if err != nil {
			if errors.Is(err, store.ErrStoreUninitialized) {
				err = errors.Join(err, ErrAbortReconcile)
			}
			return nil, err
		}

		if !exists {
			// pool is deleted, mark it for removal
			desiredPoolAFPaths[poolKey] = nil
		}
	}

	pools, err := r.poolStore.List()
	if err != nil {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
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

func (r *PodIPPoolReconciler) reconcileRoutePolicies(_ context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, lp map[string][]netip.Prefix) error {
	desiredPoolStatements, err := r.getDesiredPodIPPoolRoutePolicyStatements(p, desiredPeerAdverts, lp)
	if err != nil {
		return err
	}
	tx := r.db.WriteTxn(r.desiredRoutePolicyTable)
	defer tx.Abort()

	for poolKey, desiredStatements := range desiredPoolStatements {
		err = errors.Join(err, reconcileDesiredRoutePolicyStatements(tx, r.desiredRoutePolicyTable, p.BGPInstance.Name, r.Name(), poolKey, desiredStatements))
	}
	if err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func (r *PodIPPoolReconciler) getDesiredPodIPPoolRoutePolicyStatements(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, lp map[string][]netip.Prefix) (ResourceDesiredRoutePolicyMap, error) {
	desiredPodIPPoolRoutePolicyStatements := make(ResourceDesiredRoutePolicyMap)

	// mark for deleting pool policies
	for existing := range r.desiredRoutePolicyTable.List(r.db.ReadTxn(), bgpTables.DesiredRoutePoliciesByInstanceOwner(p.BGPInstance.Name, r.Name())) {
		_, exists, err := r.poolStore.GetByKey(existing.Resource)
		if err != nil {
			return nil, err
		}

		if !exists {
			// pool is deleted, mark it for removal
			desiredPodIPPoolRoutePolicyStatements[existing.Resource] = nil
		}
	}

	// get all pools and their route policies
	pools, err := r.poolStore.List()
	if err != nil {
		return nil, err
	}

	for _, pool := range pools {
		key := resource.Key{
			Name:      pool.Name,
			Namespace: pool.Namespace,
		}
		desiredStatements, err := r.getPodIPPoolRoutePolicyStatements(p.BGPInstance.Name, key, pool, desiredPeerAdverts, lp)
		if err != nil {
			return nil, err
		}
		desiredPodIPPoolRoutePolicyStatements[key] = desiredStatements
	}

	return desiredPodIPPoolRoutePolicyStatements, nil
}

func (r *PodIPPoolReconciler) getPodIPPoolRoutePolicyStatements(instanceName string, resourceKey resource.Key, pool *v2alpha1.CiliumPodIPPool, desiredPeerAdverts PeerAdvertisements, lp map[string][]netip.Prefix) ([]*bgpTables.DesiredRoutePolicy, error) {
	desiredStatements := []*bgpTables.DesiredRoutePolicy{}

	for peer, afAdverts := range desiredPeerAdverts {
		for family, adverts := range afAdverts {
			fam := types.ToAgentFamily(family)
			for _, advert := range adverts {
				statements, err := r.getPodIPPoolPolicyStatements(instanceName, resourceKey, peer, fam, pool, advert, lp)
				if err != nil {
					return nil, err
				}
				desiredStatements = append(desiredStatements, statements...)
			}
		}
	}

	return desiredStatements, nil
}

// populateLocalPools returns a map of allocated multi-pool IPAM CIDRs of the local CiliumNode,
// keyed by the pool name.
func (r *PodIPPoolReconciler) populateLocalPools(localNode *v2.CiliumNode) map[string][]netip.Prefix {
	if localNode == nil {
		return nil
	}

	lp := make(map[string][]netip.Prefix)
	for _, pool := range localNode.Spec.IPAM.Pools.Allocated {
		var prefixes []netip.Prefix
		for _, c := range pool.CIDRs {
			if c.IsValid() {
				prefixes = append(prefixes, c.Prefix)
			} else {
				r.logger.Error(
					"invalid IPAM pool CIDR",
					types.PrefixLogField, c,
				)
			}
		}
		lp[pool.Pool] = prefixes
	}

	return lp
}

func (r *PodIPPoolReconciler) getDesiredAFPaths(pool *v2alpha1.CiliumPodIPPool, desiredPeerAdverts PeerAdvertisements, lp map[string][]netip.Prefix) (AFPathsMap, error) {
	// Calculate desired paths per address family, collapsing per-peer advertisements into per-family advertisements.
	desiredFamilyAdverts := make(AFPathsMap)

	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// sanity check advertisement type
				if advert.AdvertisementType != v2.BGPCiliumPodIPPoolAdvert {
					r.logger.Error(
						"BUG: unexpected advertisement type",
						types.AdvertTypeLogField, advert.AdvertisementType,
					)
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
						path, err := types.NewPathForPrefix(prefix)
						if err != nil {
							return nil, fmt.Errorf("failed to create path for prefix %s: %w", prefix, err)
						}
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

func (r *PodIPPoolReconciler) getPodIPPoolPolicyStatements(instanceName string, resourceKey resource.Key, peer PeerID, family types.Family, pool *v2alpha1.CiliumPodIPPool, advert v2.BGPAdvertisement, lp map[string][]netip.Prefix) ([]*bgpTables.DesiredRoutePolicy, error) {
	if peer.Address == "" {
		return nil, nil
	}
	peerAddr, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer address: %w", err)
	}

	// check if the pool selector matches the advertisement
	poolSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed to convert label selector: %w", err)
	}

	// Ignore non matching pool.
	if !poolSelector.Matches(podIPPoolLabelSet(pool)) {
		return nil, nil
	}

	// only include pool cidrs that have been allocated to the local node.
	prefixes, exists := lp[pool.Name]
	if !exists {
		return nil, nil
	}

	var v4Prefixes, v6Prefixes types.PolicyPrefixList

	for _, prefix := range prefixes {
		if family.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
			prefixLen := int(pool.Spec.IPv4.MaskSize)
			v4Prefixes = append(v4Prefixes, types.RoutePolicyPrefix{
				CIDR:         prefix,
				PrefixLenMin: prefixLen,
				PrefixLenMax: prefixLen,
			})
		}

		if family.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
			prefixLen := int(pool.Spec.IPv6.MaskSize)
			v6Prefixes = append(v6Prefixes, types.RoutePolicyPrefix{
				CIDR:         prefix,
				PrefixLenMin: prefixLen,
				PrefixLenMax: prefixLen,
			})
		}
	}

	// if no prefixes are found for the pool, return nil
	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	name := PolicyStatementName(advert.AdvertisementType, pool.Name)
	statements, err := CreatePolicyStatements(name, peerAddr, v4Prefixes, v6Prefixes, advert)
	if err != nil {
		return nil, err
	}

	desiredStatements := make([]*bgpTables.DesiredRoutePolicy, 0, len(statements))
	for _, statement := range statements {
		desiredStatements = append(desiredStatements, &bgpTables.DesiredRoutePolicy{
			Instance:   instanceName,
			Peer:       peer.Name,
			PolicyType: types.RoutePolicyTypeExport,
			Priority:   r.Priority(),
			Owner:      r.Name(),
			Resource:   resourceKey,
			Statement:  statement,
		})
	}
	return desiredStatements, nil
}

func podIPPoolLabelSet(pool *v2alpha1.CiliumPodIPPool) labels.Labels {
	poolLabels := maps.Clone(pool.Labels)
	if poolLabels == nil {
		poolLabels = make(map[string]string)
	}
	poolLabels[podIPPoolNameLabel] = pool.Name
	poolLabels[podIPPoolNamespaceLabel] = pool.Namespace
	return labels.Set(poolLabels)
}

func (r *PodIPPoolReconciler) getMetadata(i *instance.BGPInstance) PodIPPoolReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *PodIPPoolReconciler) setMetadata(i *instance.BGPInstance, metadata PodIPPoolReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}
