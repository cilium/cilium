// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"errors"
	"maps"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging"
)

// PathMap is a map of paths indexed by the NLRI string
type PathMap map[string]*types.Path

// AFPathsMap is a map of paths per address family, indexed by the family
type AFPathsMap map[types.Family]PathMap

// ResourceAFPathsMap holds the AF paths keyed by the resource name.
type ResourceAFPathsMap map[resource.Key]AFPathsMap

// PathReference holds reference information about an advertised path
type PathReference struct {
	Count uint32
	Path  *types.Path
}

// PathReferencesMap holds path references of resources producing path advertisement, indexed by path's NLRI string
type PathReferencesMap map[string]*PathReference

type ReconcileResourceAFPathsParams struct {
	Logger                 logging.FieldLogger
	Ctx                    context.Context
	Router                 types.Router
	DesiredResourceAFPaths ResourceAFPathsMap
	CurrentResourceAFPaths ResourceAFPathsMap
}

type ReconcileAFPathsParams struct {
	Logger         logging.FieldLogger
	Ctx            context.Context
	Router         types.Router
	DesiredPaths   AFPathsMap
	CurrentPaths   AFPathsMap
	PathReferences PathReferencesMap
}

type reconcilePathsParams struct {
	Logger                logging.FieldLogger
	Ctx                   context.Context
	Router                types.Router
	CurrentAdvertisements PathMap
	ToAdvertise           PathMap
	PathReferences        PathReferencesMap
}

// ReconcileResourceAFPaths reconciles BGP advertisements per resource and address family.
// It consumes desired and current paths per resource (ResourceAFPathsMap) and returns the outcome of the reconciliation.
func ReconcileResourceAFPaths(rp ReconcileResourceAFPathsParams) (ResourceAFPathsMap, error) {
	var err error

	// compute existing path to resource references
	pathRefs := computePathReferences(rp.CurrentResourceAFPaths)

	for resKey, desiredAFPaths := range rp.DesiredResourceAFPaths {
		// check if the resource exists
		currentAFPaths, exists := rp.CurrentResourceAFPaths[resKey]
		if !exists && len(desiredAFPaths) == 0 {
			// resource does not exist in our local state, and there is nothing to advertise
			continue
		}

		// reconcile resource paths
		updatedAFPaths, rErr := ReconcileAFPaths(&ReconcileAFPathsParams{
			Logger:         rp.Logger.With(types.ResourceLogField, resKey),
			Ctx:            rp.Ctx,
			Router:         rp.Router,
			DesiredPaths:   desiredAFPaths,
			CurrentPaths:   currentAFPaths,
			PathReferences: pathRefs,
		})

		if rErr == nil && len(desiredAFPaths) == 0 {
			// no error is reported and desiredAFPaths is empty, we should delete the resource
			delete(rp.CurrentResourceAFPaths, resKey)
		} else {
			// update resource paths with returned updatedAFPaths even if there was an error.
			rp.CurrentResourceAFPaths[resKey] = updatedAFPaths
		}
		err = errors.Join(err, rErr)
	}

	return rp.CurrentResourceAFPaths, err
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
				Logger:                rp.Logger.With(types.FamilyLogField, family),
				Ctx:                   rp.Ctx,
				Router:                rp.Router,
				CurrentAdvertisements: runningPaths,
				ToAdvertise:           nil,
				PathReferences:        rp.PathReferences,
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
			PathReferences:        rp.PathReferences,
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
				l.Error("BUG: nil path in running advertisements map", types.PathLogField, advrtKey)
				continue
			}
			err := withdrawPath(params, advrtKey, advrt)
			if err != nil {
				return runningAdverts, err
			}
			delete(runningAdverts, advrtKey)
		}
		return nil, nil
	}

	for advrtKey, advrt := range params.ToAdvertise {
		if advrt == nil {
			l.Error("BUG: nil path in advertise advertisements map", types.PathLogField, advrtKey)
			continue
		}

		if _, exists := runningAdverts[advrtKey]; !exists {
			toAdvertise[advrtKey] = advrt
		}
	}

	for advrtKey, advrt := range runningAdverts {
		if advrt == nil {
			l.Error("BUG: nil path in running advertisements map", types.PathLogField, advrtKey)
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
		err := withdrawPath(params, advrtKey, advrt)
		if err != nil {
			return runningAdverts, err
		}
		delete(runningAdverts, advrtKey)
	}

	// create new adverts
	for advrtKey, advrt := range toAdvertise {
		path, err := advertisePath(params, advrtKey, advrt)
		if err != nil {
			return runningAdverts, err
		}
		runningAdverts[advrtKey] = path
	}

	return runningAdverts, nil
}

func advertisePath(params *reconcilePathsParams, pathKey string, path *types.Path) (*types.Path, error) {
	if params.PathReferences != nil {
		if ref, exists := params.PathReferences[pathKey]; exists && ref.Count > 0 {
			// path already advertised for another resource
			ref.Count += 1
			return ref.Path, nil
		}
	}

	params.Logger.Debug(
		"Advertising path",
		types.PathLogField, path.NLRI,
		types.FamilyLogField, path.Family,
	)

	advrtResp, err := params.Router.AdvertisePath(params.Ctx, types.PathRequest{Path: path})
	if err != nil {
		return nil, err
	}

	// update only in case of no error
	if params.PathReferences != nil {
		params.PathReferences[pathKey] = &PathReference{
			Count: 1,
			Path:  advrtResp.Path,
		}
	}

	return advrtResp.Path, nil
}

func withdrawPath(params *reconcilePathsParams, pathKey string, path *types.Path) error {
	if params.PathReferences != nil {
		if ref, exists := params.PathReferences[pathKey]; exists && ref.Count > 1 {
			// path still needs to be advertised for another resource
			ref.Count -= 1
			return nil
		}
	}

	params.Logger.Debug(
		"Withdrawing path",
		types.PathLogField, path.NLRI,
	)

	if err := params.Router.WithdrawPath(params.Ctx, types.PathRequest{Path: path}); err != nil {
		return err
	}

	// update only in case of no error
	if params.PathReferences != nil {
		delete(params.PathReferences, pathKey)
	}

	return nil
}

func addPathToAFPathsMap(m AFPathsMap, fam types.Family, path *types.Path) {
	pathsPerFamily, exists := m[fam]
	if !exists {
		pathsPerFamily = make(PathMap)
		m[fam] = pathsPerFamily
	}
	pathsPerFamily[path.NLRI.String()] = path
}

func computePathReferences(resourcePaths ResourceAFPathsMap) PathReferencesMap {
	pathRefs := make(PathReferencesMap)
	for _, resAFPaths := range resourcePaths {
		for _, afPaths := range resAFPaths {
			for pathKey, path := range afPaths {
				ref, exists := pathRefs[pathKey]
				if !exists {
					pathRefs[pathKey] = &PathReference{
						Count: 1,
						Path:  path,
					}
				} else {
					ref.Count += 1
				}
			}
		}
	}
	return pathRefs
}
