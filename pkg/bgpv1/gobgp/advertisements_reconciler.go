// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

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
