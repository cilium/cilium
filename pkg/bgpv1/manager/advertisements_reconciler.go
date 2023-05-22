// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type advertisementsReconcilerParams struct {
	ctx       context.Context
	name      string
	component string
	enabled   bool

	sc   *ServerWithConfig
	newc *v2alpha1api.CiliumBGPVirtualRouter

	currentAdvertisements []types.Advertisement
	toAdvertise           []netip.Prefix
}

// exportAdvertisementsReconciler reconciles the state of the BGP advertisements
// with the provided toAdvertise list and returns a list of the advertisements
// currently being announced.
func exportAdvertisementsReconciler(params *advertisementsReconcilerParams) ([]types.Advertisement, error) {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": params.component,
			},
		)
		// holds advertisements which must be advertised
		toAdvertise []types.Advertisement
		// holds advertisements which must remain in place
		toKeep []types.Advertisement
		// holds advertisements which must be removed
		toWithdraw []types.Advertisement
		// the result of advertising toAdvertise.
		newAdverts []types.Advertisement
	)

	l.Debugf("Begin reconciling %s advertisements for virtual router with local ASN %v", params.name, params.newc.LocalASN)

	// if advertisement is turned off withdraw any previously advertised
	// cidrs and early return nil.
	if !params.enabled {
		l.Debugf("%s advertisements disabled for virtual router with local ASN %v", params.name, params.newc.LocalASN)

		for _, advrt := range params.currentAdvertisements {
			l.Debugf("Withdrawing %s advertisement %v for local ASN %v", params.name, advrt.Prefix.String(), params.newc.LocalASN)
			if err := params.sc.Server.WithdrawPath(params.ctx, types.PathRequest{Advert: advrt}); err != nil {
				return nil, err
			}
		}

		return nil, nil
	}

	// an aset member which book keeps which universe it exists in
	type member struct {
		a     bool
		b     bool
		advrt *types.Advertisement
	}

	aset := map[string]*member{}

	// populate the advrts that must be present, universe a
	for _, prefix := range params.toAdvertise {
		var (
			m  *member
			ok bool
		)

		key := prefix.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				a: true,
				advrt: &types.Advertisement{
					Prefix: prefix,
				},
			}
			continue
		}
		m.a = true
	}

	// populate the advrts that are current advertised
	for _, advrt := range params.currentAdvertisements {
		var (
			m  *member
			ok bool
		)
		key := advrt.Prefix.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				b: true,
				advrt: &types.Advertisement{
					Prefix:        advrt.Prefix,
					GoBGPPathUUID: advrt.GoBGPPathUUID,
				},
			}
			continue
		}
		m.b = true
	}

	for _, m := range aset {
		// present in configured cidrs (set a) but not in advertised cidrs
		// (set b)
		if m.a && !m.b {
			toAdvertise = append(toAdvertise, *m.advrt)
		}
		// present in advertised cidrs (set b) but no in configured cidrs
		// (set b)
		if m.b && !m.a {
			toWithdraw = append(toWithdraw, *m.advrt)
		}
		// present in both configured (set a) and advertised (set b) add this to
		// cidrs to leave advertised.
		if m.b && m.a {
			toKeep = append(toKeep, *m.advrt)
		}
	}

	if len(toAdvertise) == 0 && len(toWithdraw) == 0 {
		l.Debugf("No reconciliation necessary")
		return append([]types.Advertisement{}, params.currentAdvertisements...), nil
	}

	// create new adverts
	for _, advrt := range toAdvertise {
		l.Debugf("Advertising %s %v for policy with local ASN: %v", params.name, advrt.Prefix.String(), params.newc.LocalASN)
		advrtResp, err := params.sc.Server.AdvertisePath(params.ctx, types.PathRequest{Advert: advrt})
		if err != nil {
			return nil, fmt.Errorf("failed to advertise %s prefix %v: %w", params.name, advrt.Prefix, err)
		}
		newAdverts = append(newAdverts, advrtResp.Advert)
	}

	// withdraw uneeded adverts
	for _, advrt := range toWithdraw {
		l.Debugf("Withdrawing %s %v for policy with local ASN: %v", params.name, advrt.Prefix, params.newc.LocalASN)
		if err := params.sc.Server.WithdrawPath(params.ctx, types.PathRequest{Advert: advrt}); err != nil {
			return nil, err
		}
	}

	// concat our toKeep and newAdverts slices to store the latest
	// reconciliation and return it
	return append(toKeep, newAdverts...), nil
}
