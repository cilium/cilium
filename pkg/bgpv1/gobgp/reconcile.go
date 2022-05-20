// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// ConfigReconcilerFunc is a function signature for reconciling a particular aspect
// of an old and new *v2alpha1api.CiliumBGPVirtualRouter
//
// If the `Config` field in `sc` is nil the reconciler should unconditionally
// perform the reconciliation actions, as no previous configuration is present.
type ConfigReconcilerFunc func(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error

// ConfigReconcilers is an array of ConfigReconcilerFunc(s) which should be ran
// in the defined order.
//
// Before adding ConfigReconcilerFunc consider the order in which they run and
// ensure any dependencies are reconciled first.
var ConfigReconcilers = [...]ConfigReconcilerFunc{
	preflightReconciler,
	neighborReconciler,
	exportPodCIDRReconciler,
}

// ReconcileBGPConfig will utilize the current set of ConfigReconcilerFunc(s)
// to push a BgpServer to its desired configuration.
//
// If any ConfigReconcilerFunc fails so will ReconcileBGPConfig and the caller
// is left to decide how to handle the possible inconsistent state of the
// BgpServer left over.
//
// Providing a ServerWithConfig that has a nil `Config` field indicates that
// this is the first time this BgpServer is being configured, each
// ConfigReconcilerFunc must be prepared to handle this.
//
// The two CiliumBGPVirtualRouter(s) being compared must have the same local
// ASN, unless `sc.Config` is nil, or else an error is returned.
//
// On success the provided `newc` will be written to `sc.Config`. The caller
// should then store `sc` until next reconciliation.
func ReconcileBGPConfig(ctx context.Context, m *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	if sc.Config != nil {
		if sc.Config.LocalASN != newc.LocalASN {
			return fmt.Errorf("cannot reconcile two BgpServers with different local ASNs")
		}
	}
	for _, r := range ConfigReconcilers {
		if err := r(ctx, m, sc, newc, cstate); err != nil {
			return fmt.Errorf("reconciliation of virtual router with local ASN %v failed: %w", newc.LocalASN, err)
		}
	}
	// all reconcilers succeeded so update Server's config with new peering config.
	sc.Config = newc
	return nil
}

// preflightReconciler is a preflight task before any other reconciliation should
// take place.
//
// this reconciler handles any changes in current and desired BgpState which leads
// to a recreation of an existing BgpServer.
//
// this must be done first so that the following reconciliation functions act
// upon the recreated BgpServer with the desired permanent configurations.
//
// permanent configurations for gobgp BgpServers (ones that cannot be changed after creation)
// are router ID and local listening port.
func preflightReconciler(ctx context.Context, _ *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "gobgp.preflightReconciler",
			},
		)
	)

	// If we have no config attached, we don't need to perform a preflight for
	// reconciliation.
	//
	// This is the first time this server is being registered and BGPRouterManager
	// set any fields needing reconciliation in this function already.
	if sc.Config == nil {
		l.Debugf("Preflight for virtual router with ASN %v not necessary, first instantiation of this BgpServer.", newc.LocalASN)
		return nil
	}

	l.Debugf("Begin preflight reoncilation for virtual router with ASN %v", newc.LocalASN)
	bgpInfo, err := sc.Server.GetBgp(ctx, &gobgp.GetBgpRequest{})
	if err != nil {
		return fmt.Errorf("failed to retrieve BgpServer info for virtual router with ASN %v: %w", newc.LocalASN, err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := cstate.Annotations[newc.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	// resolve router ID, if we have an annotation and it can be parsed into
	// a valid ipv4 address use this,
	//
	// if not determine if Cilium is configured with an IPv4 address, if so use
	// this.
	//
	// if neither, return an error, we cannot assign an router ID.
	var routerID string
	_, ok := cstate.Annotations[newc.LocalASN]
	switch {
	case ok && !net.ParseIP(cstate.Annotations[newc.LocalASN].RouterID).IsUnspecified():
		routerID = cstate.Annotations[newc.LocalASN].RouterID
	case !cstate.IPv4.IsUnspecified():
		routerID = cstate.IPv4.String()
	default:
		return fmt.Errorf("router id not specified by annotation and no IPv4 address assigned by cilium, cannot resolve router id for virtual router with local ASN %v", newc.LocalASN)
	}

	var shouldRecreate bool
	if localPort != bgpInfo.Global.ListenPort {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v local port has changed from %v to %v", newc.LocalASN, bgpInfo.Global.ListenPort, localPort)
	}
	if routerID != bgpInfo.Global.RouterId {
		shouldRecreate = true
		l.Infof("Virtual router with ASN %v router ID has changed from %v to %v", newc.LocalASN, bgpInfo.Global.RouterId, routerID)
	}
	if !shouldRecreate {
		l.Debugf("No preflight reconciliation necessary for virtual router with local ASN %v", newc.LocalASN)
		return nil
	}

	l.Infof("Recreating virtual router with ASN %v for changes to take effect", newc.LocalASN)

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        uint32(newc.LocalASN),
			RouterId:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &gobgp.RouteSelectionOptionsConfig{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	// stop the old BgpServer
	sc.Server.Stop()

	// create a new one via ServerWithConfig constructor
	s, err := NewServerWithConfig(ctx, startReq)
	if err != nil {
		l.WithError(err).Errorf("Failed to start BGP server for virtual router with local ASN %v", newc.LocalASN)
		return fmt.Errorf("failed to start BGP server for virtual router with local ASN %v: %w", newc.LocalASN, err)
	}

	// replace the old underlying server with our recreated one
	sc.Server = s.Server

	// dump the existing config so all subsequent reconcilers perform their
	// actions as if this is a new BgpServer.
	sc.Config = nil

	return nil
}

// neighborReconciler is a ConfigReconcilerFunc which reconciles the peers of
// the provided BGP server with the provided CiliumBGPVirtualRouter.
func neighborReconciler(ctx context.Context, _ *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, _ *agent.ControlPlaneState) error {
	if newc == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if sc == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil ServerWithConfig")
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "gobgp.neighborReconciler",
			},
		)
		toCreate []*v2alpha1api.CiliumBGPNeighbor
		toRemove []*v2alpha1api.CiliumBGPNeighbor
		curNeigh []v2alpha1api.CiliumBGPNeighbor = nil
	)
	newNeigh := newc.Neighbors
	l.Debugf("Begin reconciling peers for virtual router with local ASN %v", newc.LocalASN)

	// sc.Config can be nil if there is no previous configuration.
	if sc.Config != nil {
		curNeigh = sc.Config.Neighbors
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		a bool
		b bool
		n *v2alpha1api.CiliumBGPNeighbor
	}

	nset := map[string]*member{}

	// populate set from universe a, new neighbors
	for i, n := range newNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				a: true,
				n: &newNeigh[i],
			}
			continue
		}
		h.a = true
	}

	// populate set from universe b, current neighbors
	for i, n := range curNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				b: true,
				n: &curNeigh[i],
			}
			continue
		}
		h.b = true
	}

	for _, m := range nset {
		// present in new neighbors (set a) but not in current neighbors (set b)
		if m.a && !m.b {
			toCreate = append(toCreate, m.n)
		}
		// present in current neighbors (set b) but not in new neighbors (set a)
		if m.b && !m.a {
			toRemove = append(toRemove, m.n)
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 {
		l.Infof("Reconciling peers for virtual router with local ASN %v", newc.LocalASN)
	} else {
		l.Debugf("No peer changes necessary for virtual router with local ASN %v", newc.LocalASN)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Infof("Adding peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, newc.LocalASN)
		if err := sc.AddNeighbor(ctx, n); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Infof("Removing peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, newc.LocalASN)
		if err := sc.RemoveNeighbor(ctx, n); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	l.Infof("Done reconciling peers for virtual router with local ASN %v", newc.LocalASN)
	return nil
}

// exportPodCIDRReconciler is a ConfigReconcilerFunc which reconciles the
// advertisement of the private Kubernetes PodCIDR block.
func exportPodCIDRReconciler(ctx context.Context, _ *BGPRouterManager, sc *ServerWithConfig, newc *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	if newc == nil {
		return fmt.Errorf("attempted pod cidr export reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if cstate == nil {
		return fmt.Errorf("attempted pod cidr export reconciliation with nil ControlPlaneState")
	}
	if sc == nil {
		return fmt.Errorf("attempted pod cidr export reconciliation with nil ServerWithConfig")
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "gobgp.exportPodCIDRReconciler",
			},
		)
		// holds pod cidr advertisements which must be advertised
		toAdvertise []Advertisement
		// holds pod cidr advertisements which must remain in place
		toKeep []Advertisement
		// holds pod cidr advertisements which must be removed
		toWithdraw []Advertisement
		// a concat of toKeep + the result of advertising toAdvertise.
		// stashed onto sc.PodCIDRAnnouncements field for book keeping.
		newAdverts []Advertisement
	)

	l.Debugf("Begin reconciling pod CIDR advertisements for virtual router with local ASN %v", newc.LocalASN)

	// if we are flipping ExportPodCIDR off, withdraw any previously advertised
	// pod cidrs and early return nil.
	if !newc.ExportPodCIDR {
		l.Debugf("ExportPodCIDR disabled for virtual router with local ASN %v", newc.LocalASN)

		for _, advrt := range sc.PodCIDRAnnouncements {
			l.Debugf("Withdrawing pod CIDR advertisement %v for local ASN %v", advrt.Net.String(), newc.LocalASN)
			if err := sc.WithdrawPath(ctx, advrt); err != nil {
				return err
			}
		}

		// reslice map to dump old pod cidr state.
		sc.PodCIDRAnnouncements = sc.PodCIDRAnnouncements[:0]
		return nil
	}

	// an aset member which book keeps which universe it exists in
	type member struct {
		a     bool
		b     bool
		advrt *Advertisement
	}

	aset := map[string]*member{}

	// populate the pod cidr advrts that must be present, universe a
	for _, cidr := range cstate.PodCIDRs {
		var (
			m  *member
			ok bool
		)
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse pod cidr %s: %w", cidr, err)
		}
		key := ipNet.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				a: true,
				advrt: &Advertisement{
					Net: ipNet,
				},
			}
			continue
		}
		m.a = true
	}

	// populate the pod cidr advrts that are current advertised
	for _, advrt := range sc.PodCIDRAnnouncements {
		var (
			m  *member
			ok bool
		)
		key := advrt.Net.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				b:     true,
				advrt: &advrt,
			}
			continue
		}
		m.b = true
	}

	for _, m := range aset {
		// present in configred pod cidrs (set a) but not in advertised pod cidrs
		// (set b)
		if m.a && !m.b {
			toAdvertise = append(toAdvertise, *m.advrt)
		}
		// present in advertised pod cidrs (set b) but no in configured pod cidrs
		// (set b)
		if m.b && !m.a {
			toWithdraw = append(toWithdraw, *m.advrt)
		}
		// present in both configured (set a) and advertised (set b) add this to
		// podcidrs to leave advertised.
		if m.b && m.a {
			toKeep = append(toKeep, *m.advrt)
		}
	}

	if len(toAdvertise) == 0 && len(toWithdraw) == 0 {
		l.Debugf("No reconciliation necessary")
		return nil
	}

	// create new adverts
	for _, advrt := range toAdvertise {
		l.Debugf("Advertising pod CIDR %v for policy with local ASN: %v", advrt.Net.String(), newc.LocalASN)
		advrt, err := sc.AdvertisePath(ctx, advrt.Net)
		if err != nil {
			return fmt.Errorf("failed to advertise pod cidr prefix %v: %w", advrt.Net, err)
		}
		newAdverts = append(newAdverts, advrt)
	}

	// withdraw uneeded adverts
	for _, advrt := range toWithdraw {
		l.Debugf("Withdrawing pod CIDR %v for policy with local ASN: %v", advrt.Net, newc.LocalASN)
		if err := sc.WithdrawPath(ctx, advrt); err != nil {
			return err
		}
	}

	// concat our toKeep and newAdverts slices to store the latest reconciliation
	sc.PodCIDRAnnouncements = append(toKeep, newAdverts...)

	return nil
}
