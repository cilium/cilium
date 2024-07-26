// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

type PodCIDRReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type PodCIDRReconcilerIn struct {
	cell.In

	Logger       logrus.FieldLogger
	PeerAdvert   *CiliumPeerAdvertisement
	DaemonConfig *option.DaemonConfig
}

type PodCIDRReconciler struct {
	logger     logrus.FieldLogger
	peerAdvert *CiliumPeerAdvertisement
}

// PodCIDRReconcilerMetadata is a map of advertisements per family, key is family type
type PodCIDRReconcilerMetadata struct {
	AFPaths       AFPathsMap
	RoutePolicies RoutePolicyMap
}

func NewPodCIDRReconciler(params PodCIDRReconcilerIn) PodCIDRReconcilerOut {
	// Don't provide the reconciler if the IPAM mode is not supported
	if !types.CanAdvertisePodCIDR(params.DaemonConfig.IPAMMode()) {
		params.Logger.Info("Unsupported IPAM mode, disabling PodCIDR advertisements.")
		return PodCIDRReconcilerOut{}
	}
	return PodCIDRReconcilerOut{
		Reconciler: &PodCIDRReconciler{
			logger:     params.Logger.WithField(types.ReconcilerLogField, "PodCIDR"),
			peerAdvert: params.PeerAdvert,
		},
	}
}

func (r *PodCIDRReconciler) Name() string {
	return "PodCIDR"
}

func (r *PodCIDRReconciler) Priority() int {
	return 30
}

func (r *PodCIDRReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: PodCIDR reconciler called with nil CiliumBGPNodeConfig")
	}

	if p.CiliumNode == nil {
		return fmt.Errorf("BUG: PodCIDR reconciler called with nil CiliumNode")
	}

	// get pod CIDR prefixes
	var podCIDRPrefixes []netip.Prefix
	for _, cidr := range p.CiliumNode.Spec.IPAM.PodCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse prefix %s: %w", cidr, err)
		}
		podCIDRPrefixes = append(podCIDRPrefixes, prefix)
	}

	// get per peer per family pod cidr advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2alpha1.BGPPodCIDRAdvert)
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
		Logger:       r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:          ctx,
		Router:       p.BGPInstance.Router,
		DesiredPaths: desiredFamilyAdverts,
		CurrentPaths: metadata.AFPaths,
	})

	metadata.AFPaths = updatedAFPaths
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *PodCIDRReconciler) reconcileRoutePolicies(ctx context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, podPrefixes []netip.Prefix) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired policies
	desiredRoutePolicies, err := r.getDesiredRoutePolicies(p, desiredPeerAdverts, podPrefixes)
	if err != nil {
		return err
	}

	// reconcile route policies
	updatedPolicies, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
		Logger:          r.logger.WithField(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredRoutePolicies,
		CurrentPolicies: r.getMetadata(p.BGPInstance).RoutePolicies,
	})

	metadata.RoutePolicies = updatedPolicies
	r.setMetadata(p.BGPInstance, metadata)
	return err
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
					path := types.NewPathForPrefix(prefix)
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

func (r *PodCIDRReconciler) getDesiredRoutePolicies(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, desiredPrefixes []netip.Prefix) (RoutePolicyMap, error) {
	desiredPolicies := make(RoutePolicyMap)

	for peer, afAdverts := range desiredPeerAdverts {
		peerAddr, err := GetPeerAddressFromConfig(p.DesiredConfig, peer)
		if err != nil {
			return nil, err
		}

		for family, adverts := range afAdverts {
			fam := types.ToAgentFamily(family)

			for _, advert := range adverts {
				var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList
				for _, prefix := range desiredPrefixes {
					match := &types.RoutePolicyPrefixMatch{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()}

					if fam.Afi == types.AfiIPv4 && prefix.Addr().Is4() {
						v4Prefixes = append(v4Prefixes, match)
					}

					if fam.Afi == types.AfiIPv6 && prefix.Addr().Is6() {
						v6Prefixes = append(v6Prefixes, match)
					}
				}

				if len(v6Prefixes) > 0 || len(v4Prefixes) > 0 {
					name := PolicyName(peer, fam.Afi.String(), advert.AdvertisementType, "")
					policy, err := CreatePolicy(name, peerAddr, v4Prefixes, v6Prefixes, advert)
					if err != nil {
						return nil, err
					}
					desiredPolicies[name] = policy
				}
			}
		}
	}

	return desiredPolicies, nil
}

func (r *PodCIDRReconciler) getMetadata(i *instance.BGPInstance) PodCIDRReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = PodCIDRReconcilerMetadata{
			AFPaths:       make(AFPathsMap),
			RoutePolicies: make(RoutePolicyMap),
		}
	}
	return i.Metadata[r.Name()].(PodCIDRReconcilerMetadata)
}

func (r *PodCIDRReconciler) setMetadata(i *instance.BGPInstance, metadata PodCIDRReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}
