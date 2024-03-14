// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
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

type AFPathsMap map[types.Family][]*types.Path

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

	// get desired paths per address family
	desiredFamilyAdverts, err := r.getDesiredPathsPerFamily(p, podCIDRPrefixes)
	if err != nil {
		return err
	}

	return r.reconcileFamilyAdvertisements(ctx, p, desiredFamilyAdverts)
}

// getDesiredPathsPerFamily returns a map of desired paths per address family.
// Note: This returns prefixes per address family. Global routing table will contain prefix per family not per neighbor.
// Per neighbor advertisement will be controlled by BGP Policy.
func (r *PodCIDRReconciler) getDesiredPathsPerFamily(p ReconcileParams, desiredPrefixes []netip.Prefix) (AFPathsMap, error) {
	// get per peer per family pod cidr advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2alpha1.BGPPodCIDRAdvert)
	if err != nil {
		return nil, err
	}

	// Calculate desired paths per address family, collapsing per-peer advertisements into per-family advertisements.
	desiredFamilyAdverts := make(AFPathsMap)
	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			// create existingPathsSet for easier existence check.
			existingPathsSet := sets.New[string]()
			existingPaths, ok := desiredFamilyAdverts[agentFamily]
			if ok {
				for _, existingPath := range existingPaths {
					existingPathsSet.Insert(existingPath.NLRI.String())
				}
			} else {
				desiredFamilyAdverts[agentFamily] = make([]*types.Path, 0)
			}

			// there are some advertisements which have pod CIDR advert enabled.
			// we need to add podCIDR prefixes to the desiredFamilyAdverts.
			if len(familyAdverts) != 0 {
				var paths []*types.Path
				for _, prefix := range desiredPrefixes {
					path := types.NewPathForPrefix(prefix)
					path.Family = agentFamily

					// skip if path already exists.
					if existingPathsSet.Has(path.NLRI.String()) {
						continue
					}
					paths = append(paths, path)
				}

				desiredFamilyAdverts[agentFamily] = append(desiredFamilyAdverts[agentFamily], paths...)
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *PodCIDRReconciler) reconcileFamilyAdvertisements(ctx context.Context, p ReconcileParams, desiredPaths AFPathsMap) error {
	l := r.logger.WithFields(logrus.Fields{
		types.ReconcilerLogField: r.Name(),
		types.InstanceLogField:   p.DesiredConfig.Name,
	})
	runningState := r.getMetadata(p.BGPInstance)

	// to delete family advertisements that are not in desiredPaths
	for family := range runningState.AFPaths {
		if _, ok := desiredPaths[family]; !ok {
			runningAdverts, err := ReconcileAdvertisement(&AdvertisementsReconcilerParams{
				Logger:                l,
				Ctx:                   ctx,
				Instance:              p.BGPInstance,
				CurrentAdvertisements: runningState.AFPaths[family],
				ToAdvertise:           nil,
			})
			if err != nil {
				runningState.AFPaths[family] = runningAdverts
				return err
			}
			delete(runningState.AFPaths, family)
		}
	}

	// to update family advertisements that are in both runningState and desiredPaths
	for family := range desiredPaths {
		runningAdverts, err := ReconcileAdvertisement(&AdvertisementsReconcilerParams{
			Logger:                l,
			Ctx:                   ctx,
			Instance:              p.BGPInstance,
			CurrentAdvertisements: runningState.AFPaths[family],
			ToAdvertise:           desiredPaths[family],
		})

		// update runningState with the new advertisements
		// even on error, we want to update the runningState with current advertisements.
		runningState.AFPaths[family] = runningAdverts
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *PodCIDRReconciler) getMetadata(i *instance.BGPInstance) PodCIDRReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = PodCIDRReconcilerMetadata{
			AFPaths: make(AFPathsMap),
		}
	}
	return i.Metadata[r.Name()].(PodCIDRReconcilerMetadata)
}

func (r *PodCIDRReconciler) setMetadata(i *instance.BGPInstance, metadata PodCIDRReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}
