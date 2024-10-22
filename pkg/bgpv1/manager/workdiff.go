// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// reconcileDiff is a helper structure which provides fields and a method set
// for computing a diff of work to achieve a given
// *v2alpha1api.CiliumBGPVirtualRouter configuration.
type reconcileDiff struct {
	// incoming CiliumBGPVirtualRouter configs mapped by their
	// local ASN.
	seen map[int64]*v2alpha1api.CiliumBGPVirtualRouter
	// The local CiliumNode information at the time which reconciliation was triggered.
	ciliumNode *v2api.CiliumNode
	// Local ASNs which BgpServers must be instantiated, configured,
	// and added to the manager. Intended key for `seen` map.
	register []int64
	// Local ASNs which BgpServers exist for but current policy has marked
	// for removal. Intended key for Manager's LocalASNMap.
	withdraw []int64
	// Local ASNs which BgpServers exist for but policy associated with server
	// may have been updated and needs further reconciliation.
	// Intended key for 'seen' map.
	reconcile []int64
}

// newReconcileDiff constructs a new *reconcileDiff with all internal instructures
// initialized.
func newReconcileDiff(ciliumNode *v2api.CiliumNode) *reconcileDiff {
	return &reconcileDiff{
		seen:       make(map[int64]*v2alpha1api.CiliumBGPVirtualRouter),
		ciliumNode: ciliumNode,
		register:   []int64{},
		withdraw:   []int64{},
		reconcile:  []int64{},
	}
}

// diff computes the reconcileDiff for given an incoming
// *v2alpha1api.CiliumBGPPeeringPolicy and the current LocalASNMap state.
//
// Once diff is invoked the appropriate field will contain BgpServers to register,
// withdraw, or reconcile in the reconcileDiff's respective fields.
func (wd *reconcileDiff) diff(m LocalASNMap, policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	if err := wd.registerOrReconcileDiff(m, policy); err != nil {
		return fmt.Errorf("encountered error creating register or reconcile diff: %w", err)
	}
	if err := wd.withdrawDiff(m); err != nil {
		return fmt.Errorf("encountered error creating withdraw diff: %w", err)
	}
	return nil
}

// String provides a string representation of the reconcileDiff.
func (wd *reconcileDiff) String() string {
	return fmt.Sprintf("Registering: %v Withdrawing: %v Reconciling: %v",
		wd.register,
		wd.withdraw,
		wd.reconcile,
	)
}

// empty informs the caller whether the reconcileDiff contains any work to undertake.
func (wd *reconcileDiff) empty() bool {
	switch {
	case len(wd.register) > 0:
		fallthrough
	case len(wd.withdraw) > 0:
		fallthrough
	case len(wd.reconcile) > 0:
		return false
	}
	return true
}

// registerOrReconcileDiff will populate the `seen` field of the reconcileDiff with `policy`,
// compute BgpServers which must be registered and mark existing BgpServers for
// reconciliation of their configuration.
//
// since registerOrReconcileDiff populates the `seen` field of a diff, this method should always
// be called first when computing a reconcileDiff.
func (wd *reconcileDiff) registerOrReconcileDiff(m LocalASNMap, policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	for i, config := range policy.Spec.VirtualRouters {
		if _, ok := wd.seen[config.LocalASN]; !ok {
			wd.seen[config.LocalASN] = &policy.Spec.VirtualRouters[i]
		} else {
			return fmt.Errorf("encountered duplicate local ASNs")
		}
		if _, ok := m[config.LocalASN]; !ok {
			wd.register = append(wd.register, config.LocalASN)
		} else {
			wd.reconcile = append(wd.reconcile, config.LocalASN)
		}
	}
	return nil
}

// withdrawDiff will populate the `withdraw` field of a reconcileDiff, indicating which
// existing BgpServers must disconnected and removed from the Manager.
func (wd *reconcileDiff) withdrawDiff(m LocalASNMap) error {
	for k := range m {
		if _, ok := wd.seen[k]; !ok {
			wd.withdraw = append(wd.withdraw, k)
		}
	}
	return nil
}

type reconcileDiffV2 struct {
	seen map[string]*v2alpha1api.CiliumBGPNodeInstance

	ciliumNode *v2api.CiliumNode

	register  []string
	withdraw  []string
	reconcile []string
}

// newReconcileDiffV2 constructs a new *reconcileDiffV2 with all internal structures
// initialized.
func newReconcileDiffV2(ciliumNode *v2api.CiliumNode) *reconcileDiffV2 {
	return &reconcileDiffV2{
		seen:       make(map[string]*v2alpha1api.CiliumBGPNodeInstance),
		ciliumNode: ciliumNode,
		register:   []string{},
		withdraw:   []string{},
		reconcile:  []string{},
	}
}

func (wd *reconcileDiffV2) diff(existingInstances map[string]*instance.BGPInstance, desiredConfig *v2alpha1api.CiliumBGPNodeConfig) error {
	if err := wd.registerOrReconcileDiff(existingInstances, desiredConfig); err != nil {
		return fmt.Errorf("encountered error creating register or reconcile diff: %w", err)
	}
	if err := wd.withdrawDiff(existingInstances); err != nil {
		return fmt.Errorf("encountered error creating withdraw diff: %w", err)
	}
	return nil
}

// String provides a string representation of the reconcileDiff.
func (wd *reconcileDiffV2) String() string {
	return fmt.Sprintf("Registering: %v Withdrawing: %v Reconciling: %v",
		wd.register,
		wd.withdraw,
		wd.reconcile,
	)
}

// empty informs the caller whether the reconcileDiff contains any work to undertake.
func (wd *reconcileDiffV2) empty() bool {
	switch {
	case len(wd.register) > 0:
		fallthrough
	case len(wd.withdraw) > 0:
		fallthrough
	case len(wd.reconcile) > 0:
		return false
	}
	return true
}

// registerOrReconcileDiff will populate the `seen` field of the reconcileDiff with `policy`,
// compute BgpServers which must be registered and mark existing BgpServers for
// reconciliation of their configuration.
//
// since registerOrReconcileDiff populates the `seen` field of a diff, this method should always
// be called first when computing a reconcileDiff.
func (wd *reconcileDiffV2) registerOrReconcileDiff(existingInstances map[string]*instance.BGPInstance, desiredConfig *v2alpha1api.CiliumBGPNodeConfig) error {
	for i, config := range desiredConfig.Spec.BGPInstances {
		if _, ok := wd.seen[config.Name]; !ok {
			wd.seen[config.Name] = &desiredConfig.Spec.BGPInstances[i]
		} else {
			return fmt.Errorf("encountered duplicate BGP instance with name %s", config.Name)
		}
		if existing, ok := existingInstances[config.Name]; !ok {
			// new instance
			wd.register = append(wd.register, config.Name)
		} else {
			// existing instance
			recreate, err := wd.requiresRecreate(existing, &desiredConfig.Spec.BGPInstances[i])
			if err != nil {
				return err
			}
			if recreate {
				wd.withdraw = append(wd.withdraw, config.Name)
				wd.register = append(wd.register, config.Name) // register does an initial reconciliation as well
			} else {
				wd.reconcile = append(wd.reconcile, config.Name)
			}
		}
	}
	return nil
}

// requiresRecreate returns true if the desired config change requires full recreate of the BGP instance.
func (wd *reconcileDiffV2) requiresRecreate(existing *instance.BGPInstance, desiredConfig *v2alpha1api.CiliumBGPNodeInstance) (bool, error) {
	localASN, err := getLocalASN(desiredConfig)
	if err != nil {
		return false, fmt.Errorf("failed to get local ASN for instance %v: %w", desiredConfig.Name, err)
	}

	localPort, err := getLocalPort(desiredConfig, wd.ciliumNode, localASN)
	if err != nil {
		return false, fmt.Errorf("failed to get local port for instance %v: %w", desiredConfig.Name, err)
	}

	routerID, err := getRouterID(desiredConfig, wd.ciliumNode, localASN)
	if err != nil {
		return false, fmt.Errorf("failed to get router ID for instance %v: %w", desiredConfig.Name, err)
	}

	return localASN != int64(existing.Global.ASN) || localPort != existing.Global.ListenPort || routerID != existing.Global.RouterID, nil
}

// withdrawDiff will populate the `withdraw` field of a reconcileDiff, indicating which
// existing BgpInstances must be disconnected and removed from the Manager.
func (wd *reconcileDiffV2) withdrawDiff(existingInstances map[string]*instance.BGPInstance) error {
	for k := range existingInstances {
		if _, ok := wd.seen[k]; !ok {
			wd.withdraw = append(wd.withdraw, k)
		}
	}
	return nil
}
