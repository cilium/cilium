// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"maps"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// PathMap is a map of paths indexed by the NLRI string
type PathMap map[string]*types.Path

// AFPathsMap is a map of paths per address family, indexed by the family
type AFPathsMap map[types.Family]PathMap

// ResourceAFPathsMap holds the AF paths keyed by the resource name.
type ResourceAFPathsMap map[resource.Key]AFPathsMap

type ReconcileAFPathsParams struct {
	Logger       logrus.FieldLogger
	Ctx          context.Context
	Router       types.Router
	DesiredPaths AFPathsMap
	CurrentPaths AFPathsMap
}

type reconcilePathsParams struct {
	Logger                logrus.FieldLogger
	Ctx                   context.Context
	Router                types.Router
	CurrentAdvertisements PathMap
	ToAdvertise           PathMap
}

// ReconcileAFPaths reconciles BGP advertisements per address family. It will consume desired and current paths (AFPathsMap)
// and will return the outcome of the reconciliation.
func ReconcileAFPaths(rp *ReconcileAFPathsParams) (AFPathsMap, error) {
	runningAFPaths := make(AFPathsMap)
	maps.Copy(runningAFPaths, rp.CurrentPaths)

	// to delete family advertisements that are not in desiredPaths
	for family, runningPaths := range runningAFPaths {
		if _, ok := rp.DesiredPaths[family]; !ok {
			runningAdverts, err := reconcilePaths(&reconcilePathsParams{
				Logger:                rp.Logger,
				Ctx:                   rp.Ctx,
				Router:                rp.Router,
				CurrentAdvertisements: runningPaths,
				ToAdvertise:           nil,
			})
			if err != nil {
				runningAFPaths[family] = runningAdverts
				return runningAFPaths, err
			}
			delete(runningAFPaths, family)
		}
	}

	// to update family advertisements that are in both runningState and desiredPaths
	for family := range rp.DesiredPaths {
		runningAdverts, err := reconcilePaths(&reconcilePathsParams{
			Logger:                rp.Logger,
			Ctx:                   rp.Ctx,
			Router:                rp.Router,
			CurrentAdvertisements: runningAFPaths[family],
			ToAdvertise:           rp.DesiredPaths[family],
		})

		// update runningState with the new advertisements
		// even on error, we want to update the runningState with current advertisements.
		runningAFPaths[family] = runningAdverts
		if err != nil {
			return runningAFPaths, err
		}
	}

	return runningAFPaths, nil
}

// reconcilePaths reconciles the state of the BGP advertisements
// with the provided toAdvertise path map and returns a path map of the advertisements
// currently being announced.
// If there is an error from the BGP Router, the function will return the current advertisements in BGP router
// and the error.
func reconcilePaths(params *reconcilePathsParams) (PathMap, error) {
	var (
		// logger for the reconciler
		l = params.Logger
		// holds advertisements which must be advertised
		toAdvertise = make(PathMap)
		// holds advertisements which must be removed
		toWithdraw = make(PathMap)
	)

	// running advertisements
	runningAdverts := make(PathMap)
	maps.Copy(runningAdverts, params.CurrentAdvertisements)

	// if there are no advertisements to be made, we will withdraw all current advertisements
	if len(params.ToAdvertise) == 0 {
		for advrtKey, advrt := range runningAdverts {
			if advrt == nil {
				l.WithField(types.PathLogField, advrtKey).Error("BUG: nil path in running advertisements map")
				continue
			}

			l.WithFields(logrus.Fields{
				types.PathLogField:   advrt.NLRI.String(),
				types.FamilyLogField: advrt.Family.String(),
			}).Debug("Withdrawing path")

			if err := params.Router.WithdrawPath(params.Ctx, types.PathRequest{Path: advrt}); err != nil {
				return runningAdverts, err
			}
			delete(runningAdverts, advrtKey)
		}
		return nil, nil
	}

	for advrtKey, advrt := range params.ToAdvertise {
		if advrt == nil {
			l.WithField(types.PathLogField, advrtKey).Error("BUG: nil path in advertise advertisements map")
			continue
		}

		if _, exists := runningAdverts[advrtKey]; !exists {
			toAdvertise[advrtKey] = advrt
		}
	}

	for advrtKey, advrt := range runningAdverts {
		if advrt == nil {
			l.WithField(types.PathLogField, advrtKey).Error("BUG: nil path in running advertisements map")
			continue
		}

		if _, exists := params.ToAdvertise[advrtKey]; !exists {
			toWithdraw[advrtKey] = advrt
		}
	}

	if len(toAdvertise) == 0 && len(toWithdraw) == 0 {
		l.Debug("no reconciliation necessary")
		return params.CurrentAdvertisements, nil
	}

	// withdraw unneeded adverts
	for advrtKey, advrt := range toWithdraw {
		l.WithFields(logrus.Fields{
			types.PathLogField:   advrt.NLRI.String(),
			types.FamilyLogField: advrt.Family.String(),
		}).Debug("Withdrawing path")

		if err := params.Router.WithdrawPath(params.Ctx, types.PathRequest{Path: advrt}); err != nil {
			return runningAdverts, err
		}
		delete(runningAdverts, advrtKey)
	}

	// create new adverts
	for advrtKey, advrt := range toAdvertise {
		l.WithFields(logrus.Fields{
			types.PathLogField:   advrt.NLRI.String(),
			types.FamilyLogField: advrt.Family.String(),
		}).Debug("Advertising path")

		advrtResp, err := params.Router.AdvertisePath(params.Ctx, types.PathRequest{Path: advrt})
		if err != nil {
			return runningAdverts, err
		}
		runningAdverts[advrtKey] = advrtResp.Path
	}

	return runningAdverts, nil
}

func addPathToAFPathsMap(m AFPathsMap, fam types.Family, path *types.Path) {
	pathsPerFamily, exists := m[fam]
	if !exists {
		pathsPerFamily = make(PathMap)
		m[fam] = pathsPerFamily
	}
	pathsPerFamily[path.NLRI.String()] = path
}
