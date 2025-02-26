// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
)

type advertisementsReconcilerParams struct {
	logger    logging.FieldLogger
	ctx       context.Context
	name      string
	component string
	enabled   bool

	sc   *instance.ServerWithConfig
	newc *v2alpha1api.CiliumBGPVirtualRouter

	currentAdvertisements []*types.Path
	toAdvertise           []*types.Path
}

// exportAdvertisementsReconciler reconciles the state of the BGP advertisements
// with the provided toAdvertise list and returns a list of the advertisements
// currently being announced.
func exportAdvertisementsReconciler(params *advertisementsReconcilerParams) ([]*types.Path, error) {
	var (
		logAttr = slog.String("component", params.component)
		// holds advertisements which must be advertised
		toAdvertise []*types.Path
		// holds advertisements which must remain in place
		toKeep []*types.Path
		// holds advertisements which must be removed
		toWithdraw []*types.Path
		// the result of advertising toAdvertise.
		newAdverts []*types.Path
	)

	params.logger.Debug("Begin reconciling advertisements for virtual router with local ASN", slog.String("name", params.name), slog.Int64("asn", params.newc.LocalASN), logAttr)

	// if advertisement is turned off withdraw any previously advertised
	// cidrs and early return nil.
	if !params.enabled {
		params.logger.Debug("advertisements disabled for virtual router with local ASN", slog.String("name", params.name), slog.Int64("asn", params.newc.LocalASN), logAttr)

		for _, advrt := range params.currentAdvertisements {
			params.logger.Debug("Withdrawing advertisement for local ASN", slog.String("name", params.name), slog.Any("NLRI", advrt.NLRI), slog.Int64("asn", params.newc.LocalASN), logAttr)
			if err := params.sc.Server.WithdrawPath(params.ctx, types.PathRequest{Path: advrt}); err != nil {
				return nil, err
			}
		}

		return nil, nil
	}

	// an aset member which book keeps which universe it exists in
	type member struct {
		a     bool
		b     bool
		advrt *types.Path
	}

	aset := map[string]*member{}

	// populate the advrts that must be present, universe a
	for _, path := range params.toAdvertise {
		var (
			m  *member
			ok bool
		)

		key := path.NLRI.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				a:     true,
				advrt: path,
			}
			continue
		}
		m.a = true
	}

	// populate the advrts that are current advertised
	for _, path := range params.currentAdvertisements {
		var (
			m  *member
			ok bool
		)
		key := path.NLRI.String()
		if m, ok = aset[key]; !ok {
			aset[key] = &member{
				b:     true,
				advrt: path,
			}
			continue
		}
		m.b = true
	}

	for _, m := range aset {
		// present in configured cidrs (set a) but not in advertised cidrs
		// (set b)
		if m.a && !m.b {
			toAdvertise = append(toAdvertise, m.advrt)
		}
		// present in advertised cidrs (set b) but no in configured cidrs
		// (set b)
		if m.b && !m.a {
			toWithdraw = append(toWithdraw, m.advrt)
		}
		// present in both configured (set a) and advertised (set b) add this to
		// cidrs to leave advertised.
		if m.b && m.a {
			toKeep = append(toKeep, m.advrt)
		}
	}

	if len(toAdvertise) == 0 && len(toWithdraw) == 0 {
		params.logger.Debug("No reconciliation necessary", logAttr)
		return append([]*types.Path{}, params.currentAdvertisements...), nil
	}

	// create new adverts
	for _, advrt := range toAdvertise {
		params.logger.Debug("Advertising for policy with local ASN", slog.String("name", params.name), slog.Any("NLRI", advrt.NLRI), slog.Int64("asn", params.newc.LocalASN), logAttr)
		advrtResp, err := params.sc.Server.AdvertisePath(params.ctx, types.PathRequest{Path: advrt})
		if err != nil {
			return nil, fmt.Errorf("failed to advertise %s prefix %v: %w", params.name, advrt.NLRI, err)
		}
		newAdverts = append(newAdverts, advrtResp.Path)
	}

	// withdraw unneeded adverts
	for _, advrt := range toWithdraw {
		params.logger.Debug("Withdrawing for policy with local ASN", slog.String("name", params.name), slog.Any("NLRI", advrt.NLRI), slog.Int64("asn", params.newc.LocalASN), logAttr)
		if err := params.sc.Server.WithdrawPath(params.ctx, types.PathRequest{Path: advrt}); err != nil {
			return nil, err
		}
	}

	// concat our toKeep and newAdverts slices to store the latest
	// reconciliation and return it
	return append(toKeep, newAdverts...), nil
}
