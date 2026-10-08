// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type PodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type PodCIDRReconcilerIn struct {
	cell.In

	Logger       *slog.Logger
	PeerAdvert   *CiliumPeerAdvertisement
	DaemonConfig *option.DaemonConfig

	DB                      *statedb.DB
	DesiredRoutePolicyTable statedb.RWTable[*bgpTables.DesiredRoutePolicy]
}

type PodCIDRReconciler struct {
	logger                  *slog.Logger
	peerAdvert              *CiliumPeerAdvertisement
	db                      *statedb.DB
	desiredRoutePolicyTable statedb.RWTable[*bgpTables.DesiredRoutePolicy]
	metadata                map[string]PodCIDRReconcilerMetadata
}

// PodCIDRReconcilerMetadata is a map of advertisements per family, key is family type
type PodCIDRReconcilerMetadata struct {
	AFPaths AFPathsMap
}

func NewPodCIDRReconciler(params PodCIDRReconcilerIn) PodCIDRReconcilerOut {
	// Don't provide the reconciler if the IPAM mode is not supported
	if !types.CanAdvertisePodCIDR(params.DaemonConfig.IPAMMode()) {
		params.Logger.Info("Unsupported IPAM mode, disabling PodCIDR advertisements.")
		return PodCIDRReconcilerOut{}
	}
	return PodCIDRReconcilerOut{
		Reconciler: &PodCIDRReconciler{
			logger:                  params.Logger.With(types.ReconcilerLogField, "PodCIDR"),
			peerAdvert:              params.PeerAdvert,
			db:                      params.DB,
			desiredRoutePolicyTable: params.DesiredRoutePolicyTable,
			metadata:                make(map[string]PodCIDRReconcilerMetadata),
		},
	}
}

func (r *PodCIDRReconciler) Name() string {
	return PodCIDRReconcilerName
}

func (r *PodCIDRReconciler) Priority() int {
	return PodCIDRReconcilerPriority
}

func (r *PodCIDRReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = PodCIDRReconcilerMetadata{
		AFPaths: make(AFPathsMap),
	}
	return nil
}

func (r *PodCIDRReconciler) Cleanup(i *instance.BGPInstance) {
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

func (r *PodCIDRReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	// get pod CIDR prefixes
	var podCIDRPrefixes []netip.Prefix
	for _, cidr := range p.CiliumNode.Spec.IPAM.PodCIDRs {
		podCIDRPrefixes = append(podCIDRPrefixes, cidr.Prefix)
	}

	// get per peer per family pod cidr advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2.BGPPodCIDRAdvert)
	if err != nil {
		return err
	}

	err = r.reconcileRoutePolicies(ctx, p, desiredPeerAdverts, podCIDRPrefixes)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, p, desiredPeerAdverts, podCIDRPrefixes)
}

func (r *PodCIDRReconciler) reconcilePaths(ctx context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, podPrefixes []netip.Prefix) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired paths per address family
	desiredFamilyAdverts, err := r.getDesiredPathsPerFamily(desiredPeerAdverts, podPrefixes)
	if err != nil {
		return err
	}

	// reconcile family advertisements
	updatedAFPaths, err := ReconcileAFPaths(&ReconcileAFPathsParams{
		Logger:       r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:          ctx,
		Router:       p.BGPInstance.Router,
		DesiredPaths: desiredFamilyAdverts,
		CurrentPaths: metadata.AFPaths,
	})

	metadata.AFPaths = updatedAFPaths
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *PodCIDRReconciler) reconcileRoutePolicies(_ context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, podPrefixes []netip.Prefix) error {
	desiredStatements, err := r.getDesiredRoutePolicyStatements(p.BGPInstance.Name, desiredPeerAdverts, podPrefixes)
	if err != nil {
		return err
	}
	tx := r.db.WriteTxn(r.desiredRoutePolicyTable)
	defer tx.Abort()

	if err := reconcileDesiredRoutePolicyStatements(tx, r.desiredRoutePolicyTable, p.BGPInstance.Name, r.Name(), resource.Key{}, desiredStatements); err != nil {
		return err
	}
	tx.Commit()
	return nil
}

// getDesiredPathsPerFamily returns a map of desired paths per address family.
// Note: This returns prefixes per address family. Global routing table will contain prefix per family not per neighbor.
// Per neighbor advertisement will be controlled by BGP Policy.
func (r *PodCIDRReconciler) getDesiredPathsPerFamily(desiredPeerAdverts PeerAdvertisements, desiredPrefixes []netip.Prefix) (AFPathsMap, error) {
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

			// there are some advertisements which have pod CIDR advert enabled.
			// we need to add podCIDR prefixes to the desiredFamilyAdverts.
			if len(familyAdverts) != 0 {
				for _, prefix := range desiredPrefixes {
					path, err := types.NewPathForPrefix(prefix)
					if err != nil {
						return nil, fmt.Errorf("failed to create path for prefix %s: %w", prefix, err)
					}
					path.Family = agentFamily

					// we only add path corresponding to the family of the prefix.
					if agentFamily.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						pathsPerFamily[path.NLRI.String()] = path
					}
					if agentFamily.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						pathsPerFamily[path.NLRI.String()] = path
					}
				}
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *PodCIDRReconciler) getDesiredRoutePolicyStatements(instanceName string, desiredPeerAdverts PeerAdvertisements, desiredPrefixes []netip.Prefix) ([]*bgpTables.DesiredRoutePolicy, error) {
	desiredStatements := []*bgpTables.DesiredRoutePolicy{}

	for peer, afAdverts := range desiredPeerAdverts {
		if peer.Address == "" {
			continue
		}
		peerAddr, err := netip.ParseAddr(peer.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}

		for family, adverts := range afAdverts {
			fam := types.ToAgentFamily(family)

			for _, advert := range adverts {
				var v4Prefixes, v6Prefixes types.PolicyPrefixList
				for _, prefix := range desiredPrefixes {
					rpPrefix := types.RoutePolicyPrefix{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()}

					if fam.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						v4Prefixes = append(v4Prefixes, rpPrefix)
					}

					if fam.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						v6Prefixes = append(v6Prefixes, rpPrefix)
					}
				}

				if len(v6Prefixes) > 0 || len(v4Prefixes) > 0 {
					name := PolicyStatementName(advert.AdvertisementType, "")
					statements, err := CreatePolicyStatements(name, peerAddr, v4Prefixes, v6Prefixes, advert)
					if err != nil {
						return nil, err
					}
					for _, statement := range statements {
						desiredStatements = append(desiredStatements, &bgpTables.DesiredRoutePolicy{
							Instance:   instanceName,
							Peer:       peer.Name,
							PolicyType: types.RoutePolicyTypeExport,
							Priority:   r.Priority(),
							Owner:      r.Name(),
							Statement:  statement,
						})
					}
				}
			}
		}
	}

	return desiredStatements, nil
}

func (r *PodCIDRReconciler) getMetadata(i *instance.BGPInstance) PodCIDRReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *PodCIDRReconciler) setMetadata(i *instance.BGPInstance, metadata PodCIDRReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}
