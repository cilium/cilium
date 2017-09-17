/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package persistentvolume

import (
	"fmt"
	"sort"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	v1helper "k8s.io/kubernetes/pkg/api/v1/helper"
	"k8s.io/kubernetes/pkg/volume"
)

// persistentVolumeOrderedIndex is a cache.Store that keeps persistent volumes
// indexed by AccessModes and ordered by storage capacity.
type persistentVolumeOrderedIndex struct {
	store cache.Indexer
}

func newPersistentVolumeOrderedIndex() persistentVolumeOrderedIndex {
	return persistentVolumeOrderedIndex{cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{"accessmodes": accessModesIndexFunc})}
}

// accessModesIndexFunc is an indexing function that returns a persistent
// volume's AccessModes as a string
func accessModesIndexFunc(obj interface{}) ([]string, error) {
	if pv, ok := obj.(*v1.PersistentVolume); ok {
		modes := v1helper.GetAccessModesAsString(pv.Spec.AccessModes)
		return []string{modes}, nil
	}
	return []string{""}, fmt.Errorf("object is not a persistent volume: %v", obj)
}

// listByAccessModes returns all volumes with the given set of
// AccessModeTypes. The list is unsorted!
func (pvIndex *persistentVolumeOrderedIndex) listByAccessModes(modes []v1.PersistentVolumeAccessMode) ([]*v1.PersistentVolume, error) {
	pv := &v1.PersistentVolume{
		Spec: v1.PersistentVolumeSpec{
			AccessModes: modes,
		},
	}

	objs, err := pvIndex.store.Index("accessmodes", pv)
	if err != nil {
		return nil, err
	}

	volumes := make([]*v1.PersistentVolume, len(objs))
	for i, obj := range objs {
		volumes[i] = obj.(*v1.PersistentVolume)
	}

	return volumes, nil
}

// find returns the nearest PV from the ordered list or nil if a match is not found
func (pvIndex *persistentVolumeOrderedIndex) findByClaim(claim *v1.PersistentVolumeClaim) (*v1.PersistentVolume, error) {
	// PVs are indexed by their access modes to allow easier searching.  Each
	// index is the string representation of a set of access modes. There is a
	// finite number of possible sets and PVs will only be indexed in one of
	// them (whichever index matches the PV's modes).
	//
	// A request for resources will always specify its desired access modes.
	// Any matching PV must have at least that number of access modes, but it
	// can have more.  For example, a user asks for ReadWriteOnce but a GCEPD
	// is available, which is ReadWriteOnce+ReadOnlyMany.
	//
	// Searches are performed against a set of access modes, so we can attempt
	// not only the exact matching modes but also potential matches (the GCEPD
	// example above).
	allPossibleModes := pvIndex.allPossibleMatchingAccessModes(claim.Spec.AccessModes)

	var smallestVolume *v1.PersistentVolume
	var smallestVolumeQty resource.Quantity
	requestedQty := claim.Spec.Resources.Requests[v1.ResourceName(v1.ResourceStorage)]
	requestedClass := v1helper.GetPersistentVolumeClaimClass(claim)

	var selector labels.Selector
	if claim.Spec.Selector != nil {
		internalSelector, err := metav1.LabelSelectorAsSelector(claim.Spec.Selector)
		if err != nil {
			// should be unreachable code due to validation
			return nil, fmt.Errorf("error creating internal label selector for claim: %v: %v", claimToClaimKey(claim), err)
		}
		selector = internalSelector
	}

	for _, modes := range allPossibleModes {
		volumes, err := pvIndex.listByAccessModes(modes)
		if err != nil {
			return nil, err
		}

		// Go through all available volumes with two goals:
		// - find a volume that is either pre-bound by user or dynamically
		//   provisioned for this claim. Because of this we need to loop through
		//   all volumes.
		// - find the smallest matching one if there is no volume pre-bound to
		//   the claim.
		for _, volume := range volumes {
			if isVolumeBoundToClaim(volume, claim) {
				// this claim and volume are pre-bound; return
				// the volume if the size request is satisfied,
				// otherwise continue searching for a match
				volumeQty := volume.Spec.Capacity[v1.ResourceStorage]
				if volumeQty.Cmp(requestedQty) < 0 {
					continue
				}
				return volume, nil
			}

			// filter out:
			// - volumes bound to another claim
			// - volumes whose labels don't match the claim's selector, if specified
			// - volumes in Class that is not requested
			if volume.Spec.ClaimRef != nil {
				continue
			} else if selector != nil && !selector.Matches(labels.Set(volume.Labels)) {
				continue
			}
			if v1helper.GetPersistentVolumeClass(volume) != requestedClass {
				continue
			}

			volumeQty := volume.Spec.Capacity[v1.ResourceStorage]
			if volumeQty.Cmp(requestedQty) >= 0 {
				if smallestVolume == nil || smallestVolumeQty.Cmp(volumeQty) > 0 {
					smallestVolume = volume
					smallestVolumeQty = volumeQty
				}
			}
		}

		if smallestVolume != nil {
			// Found a matching volume
			return smallestVolume, nil
		}
	}
	return nil, nil
}

// findBestMatchForClaim is a convenience method that finds a volume by the claim's AccessModes and requests for Storage
func (pvIndex *persistentVolumeOrderedIndex) findBestMatchForClaim(claim *v1.PersistentVolumeClaim) (*v1.PersistentVolume, error) {
	return pvIndex.findByClaim(claim)
}

// allPossibleMatchingAccessModes returns an array of AccessMode arrays that
// can satisfy a user's requested modes.
//
// see comments in the Find func above regarding indexing.
//
// allPossibleMatchingAccessModes gets all stringified accessmodes from the
// index and returns all those that contain at least all of the requested
// mode.
//
// For example, assume the index contains 2 types of PVs where the stringified
// accessmodes are:
//
// "RWO,ROX" -- some number of GCEPDs
// "RWO,ROX,RWX" -- some number of NFS volumes
//
// A request for RWO could be satisfied by both sets of indexed volumes, so
// allPossibleMatchingAccessModes returns:
//
// [][]v1.PersistentVolumeAccessMode {
//      []v1.PersistentVolumeAccessMode {
//			v1.ReadWriteOnce, v1.ReadOnlyMany,
//		},
//      []v1.PersistentVolumeAccessMode {
//			v1.ReadWriteOnce, v1.ReadOnlyMany, v1.ReadWriteMany,
//		},
// }
//
// A request for RWX can be satisfied by only one set of indexed volumes, so
// the return is:
//
// [][]v1.PersistentVolumeAccessMode {
//      []v1.PersistentVolumeAccessMode {
//			v1.ReadWriteOnce, v1.ReadOnlyMany, v1.ReadWriteMany,
//		},
// }
//
// This func returns modes with ascending levels of modes to give the user
// what is closest to what they actually asked for.
func (pvIndex *persistentVolumeOrderedIndex) allPossibleMatchingAccessModes(requestedModes []v1.PersistentVolumeAccessMode) [][]v1.PersistentVolumeAccessMode {
	matchedModes := [][]v1.PersistentVolumeAccessMode{}
	keys := pvIndex.store.ListIndexFuncValues("accessmodes")
	for _, key := range keys {
		indexedModes := v1helper.GetAccessModesFromString(key)
		if volume.AccessModesContainedInAll(indexedModes, requestedModes) {
			matchedModes = append(matchedModes, indexedModes)
		}
	}

	// sort by the number of modes in each array with the fewest number of
	// modes coming first. this allows searching for volumes by the minimum
	// number of modes required of the possible matches.
	sort.Sort(byAccessModes{matchedModes})
	return matchedModes
}

// byAccessModes is used to order access modes by size, with the fewest modes first
type byAccessModes struct {
	modes [][]v1.PersistentVolumeAccessMode
}

func (c byAccessModes) Less(i, j int) bool {
	return len(c.modes[i]) < len(c.modes[j])
}

func (c byAccessModes) Swap(i, j int) {
	c.modes[i], c.modes[j] = c.modes[j], c.modes[i]
}

func (c byAccessModes) Len() int {
	return len(c.modes)
}

func claimToClaimKey(claim *v1.PersistentVolumeClaim) string {
	return fmt.Sprintf("%s/%s", claim.Namespace, claim.Name)
}

func claimrefToClaimKey(claimref *v1.ObjectReference) string {
	return fmt.Sprintf("%s/%s", claimref.Namespace, claimref.Name)
}
