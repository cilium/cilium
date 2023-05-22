// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// reconcileDiff is a helper structure which provides fields and a method set
// for computing a diff of work to achieve a given
// *v2alpha1api.CiliumBGPVirtualRouter configuration.
type reconcileDiff struct {
	// incoming CiliumBGPVirtualRouter configs mapped by their
	// local ASN.
	seen map[int]*v2alpha1api.CiliumBGPVirtualRouter
	// the state of the bgp control plane at the time of this reconcileDiff's
	// creation.
	state *agent.ControlPlaneState
	// Local ASNs which BgpServers must be instantiated, configured,
	// and added to the manager. Intended key for `seen` map.
	register []int
	// Local ASNs which BgpServers exist for but current policy has marked
	// for removal. Intended key for Manager's LocalASNMap.
	withdraw []int
	// Local ASNs which BgpServers exist for but policy associated with server
	// may have been updated and needs further reconciliation.
	// Intended key for 'seen' map.
	reconcile []int
}

// newReconcileDiff constructs a new *reconcileDiff with all internal instructures
// initialized.
func newReconcileDiff(state *agent.ControlPlaneState) *reconcileDiff {
	return &reconcileDiff{
		seen:      make(map[int]*v2alpha1api.CiliumBGPVirtualRouter),
		state:     state,
		register:  []int{},
		withdraw:  []int{},
		reconcile: []int{},
	}
}

// diff computes the reconcileDiff for given an incoming
// *v2alpha1api.CiliumBGPPeeringPolicy and the current LocalASNMap state.
//
// Once diff is invoked the appropriate field will contain BgpServers to register,
// withdraw, or reconcile in the reconcileDiff's respective fields.
func (wd *reconcileDiff) diff(m LocalASNMap, policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	if err := wd.registerOrReconcileDiff(m, policy); err != nil {
		return fmt.Errorf("encountered error creating reoncile diff: %v", err)
	}
	if err := wd.withdrawDiff(m, policy); err != nil {
		return fmt.Errorf("encountered error creating reconcile diff: %v", err)
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

// withdrawDiff will populate the `remove` field of a reconcileDiff, indicating which
// existing BgpServers must disconnected and removed from the Manager.
func (wd *reconcileDiff) withdrawDiff(m LocalASNMap, policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	for k := range m {
		if _, ok := wd.seen[k]; !ok {
			wd.withdraw = append(wd.withdraw, k)
		}
	}
	return nil
}
