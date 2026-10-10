/*
Copyright 2023 The Kubernetes Authors.

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

package suite

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
)

// -----------------------------------------------------------------------------
// Conformance Profiles - Public Types
// -----------------------------------------------------------------------------

// ConformanceProfile is a group of features that have a related purpose, e.g.
// to cover a specific feature present in Network Policy V2 API.
//
// For more details see the relevant NPEP: https://network-policy-api.sigs.k8s.io/npeps/npep-137/
type ConformanceProfile struct {
	Name                 ConformanceProfileName
	StandardFeatures     sets.Set[SupportedFeature]
	ExperimentalFeatures sets.Set[SupportedFeature]
}

type ConformanceProfileName string

const (
	// CNPConformanceProfileName indicates the name of the conformance profile
	// which covers ClusterNetworkPolicy core API
	CNPConformanceProfileName ConformanceProfileName = "ClusterNetworkPolicy"
)

// -----------------------------------------------------------------------------
// Conformance Profiles - Public Vars
// -----------------------------------------------------------------------------

var (
	// CNPConformanceProfile is a ConformanceProfile that covers testing CNP API
	CNPConformanceProfile = ConformanceProfile{
		Name: CNPConformanceProfileName,
		StandardFeatures: sets.New(
			SupportClusterNetworkPolicy,
		),
		ExperimentalFeatures: sets.New(
			SupportClusterNetworkPolicyNamedPorts,
			SupportClusterNetworkPolicyEgressNodePeers,
		),
	}
)

// -----------------------------------------------------------------------------
// Conformance Profiles - Private Profile Mapping Helpers
// -----------------------------------------------------------------------------

// conformanceProfileMap maps short human-readable names to their respective
// ConformanceProfiles.
var conformanceProfileMap = map[ConformanceProfileName]ConformanceProfile{
	CNPConformanceProfileName: CNPConformanceProfile,
}

// getConformanceProfileForName retrieves a known ConformanceProfile by it's simple
// human readable ConformanceProfileName.
func getConformanceProfileForName(name ConformanceProfileName) (ConformanceProfile, error) {
	profile, ok := conformanceProfileMap[name]
	if !ok {
		return profile, fmt.Errorf("%s is not a valid conformance profile", name)
	}

	return profile, nil
}

// getConformanceProfilesForTest retrieves the ConformanceProfiles a test belongs to.
func getConformanceProfilesForTest(test ConformanceTest, conformanceProfiles sets.Set[ConformanceProfileName]) sets.Set[*ConformanceProfile] {
	matchingConformanceProfiles := sets.New[*ConformanceProfile]()
	for _, conformanceProfileName := range conformanceProfiles.UnsortedList() {
		cp := conformanceProfileMap[conformanceProfileName]
		hasAllFeatures := true
		for _, feature := range test.Features {
			if !cp.StandardFeatures.Has(feature) && !cp.ExperimentalFeatures.Has(feature) {
				hasAllFeatures = false
				break
			}
		}
		if hasAllFeatures {
			matchingConformanceProfiles.Insert(&cp)
		}
	}

	return matchingConformanceProfiles
}
