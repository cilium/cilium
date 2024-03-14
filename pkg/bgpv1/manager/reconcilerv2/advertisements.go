// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

type AdvertisementsReconcilerParams struct {
	Logger                logrus.FieldLogger
	Ctx                   context.Context
	Instance              *instance.BGPInstance
	CurrentAdvertisements []*types.Path
	ToAdvertise           []*types.Path
}

// ReconcileAdvertisement reconciles the state of the BGP advertisements
// with the provided toAdvertise list and returns a list of the advertisements
// currently being announced.
// If there is an error from the BGP Router, the function will return the current advertisements in BGP router
// and the error.
func ReconcileAdvertisement(params *AdvertisementsReconcilerParams) ([]*types.Path, error) {
	var (
		// logger for the reconciler
		l = params.Logger
		// holds advertisements which must be advertised
		toAdvertise []*types.Path
		// holds advertisements which must remain in place
		toKeep []*types.Path
		// holds advertisements which must be removed
		toWithdraw []*types.Path
	)

	// if there are no advertisements to be made, we will withdraw all current advertisements
	if len(params.ToAdvertise) == 0 {
		for i, advrt := range params.CurrentAdvertisements {
			l.WithFields(logrus.Fields{
				types.PathLogField:   advrt.NLRI.String(),
				types.FamilyLogField: advrt.Family.String(),
			}).Debug("Withdrawing path")

			if err := params.Instance.Router.WithdrawPath(params.Ctx, types.PathRequest{Path: advrt}); err != nil {
				// upto ith index, all advertisements are withdrawn.
				// return the remaining advertisements and the error
				return append([]*types.Path{}, params.CurrentAdvertisements[i:]...), err
			}
		}

		return nil, nil
	}

	// an aset member which book keeps which universe it exists in
	type member struct {
		configured bool
		advertised bool
		advrt      *types.Path
	}

	aset := map[string]*member{}

	// populate the advrts that must be present, universe a
	for _, path := range params.ToAdvertise {
		key := path.NLRI.String()
		if _, ok := aset[key]; !ok {
			aset[key] = &member{
				configured: true,
				advrt:      path,
			}
		}
	}

	// populate the advrts that are current advertised
	for _, path := range params.CurrentAdvertisements {
		key := path.NLRI.String()
		m, ok := aset[key]
		if !ok {
			aset[key] = &member{
				advertised: true,
				advrt:      path,
			}
			continue
		}
		m.advertised = true
	}

	for _, m := range aset {
		// present in configured cidrs (set configured) but not in advertised cidrs
		// (set advertised)
		if m.configured && !m.advertised {
			toAdvertise = append(toAdvertise, m.advrt)
		}
		// present in advertised cidrs (set advertised) but not in configured cidrs
		// (set configured)
		if m.advertised && !m.configured {
			toWithdraw = append(toWithdraw, m.advrt)
		}
		// present in both configured (set configured) and advertised (set advertised) add this to
		// cidrs to keep.
		if m.configured && m.advertised {
			toKeep = append(toKeep, m.advrt)
		}
	}

	if len(toAdvertise) == 0 && len(toWithdraw) == 0 {
		l.Debug("no reconciliation necessary")
		return append([]*types.Path{}, params.CurrentAdvertisements...), nil
	}

	// running paths is the list of paths that are currently being advertised, as we add/remove we will update this list.
	runningPaths := toKeep

	// create new adverts
	for _, advrt := range toAdvertise {
		l.WithFields(logrus.Fields{
			types.PathLogField:   advrt.NLRI.String(),
			types.FamilyLogField: advrt.Family.String(),
		}).Debug("Advertising path")

		advrtResp, err := params.Instance.Router.AdvertisePath(params.Ctx, types.PathRequest{Path: advrt})
		if err != nil {
			return runningPaths, err
		}
		runningPaths = append(runningPaths, advrtResp.Path)
	}

	// withdraw unneeded adverts
	for i, advrt := range toWithdraw {
		l.WithFields(logrus.Fields{
			types.PathLogField:   advrt.NLRI.String(),
			types.FamilyLogField: advrt.Family.String(),
		}).Debug("Withdrawing path")

		if err := params.Instance.Router.WithdrawPath(params.Ctx, types.PathRequest{Path: advrt}); err != nil {
			// upto ith index, all advertisements are withdrawn.
			// add remaining advertisements to runningPaths
			runningPaths = append(runningPaths, toWithdraw[i:]...)
			return runningPaths, err
		}
	}

	return runningPaths, nil
}
