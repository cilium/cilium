/*
Copyright 2022 The Kubernetes Authors.

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

package features

import "k8s.io/apimachinery/pkg/util/sets"

// -----------------------------------------------------------------------------
// Features - Types
// -----------------------------------------------------------------------------

// FeatureName is the type used to represent the name of a feature.
type FeatureName string

// FeatureChannel is the type used to represent the channel a feature belongs to.
type FeatureChannel string

const (
	// FeatureChannelExperimental is used for experimental features.
	FeatureChannelExperimental = "experimental"
	// FeatureChannelStandard is used for standard features.
	FeatureChannelStandard = "standard"
)

// Feature is a struct that represents a feature.
type Feature struct {
	Name    FeatureName
	Channel FeatureChannel
}

// -----------------------------------------------------------------------------
// Features - Compilations
// -----------------------------------------------------------------------------

// AllFeatures contains all the supported features and can be used to run all
// conformance tests with `all-features` flag.
//
// NOTE: as new feature sets are added they should be inserted into this set.

var (
	AllFeatures = sets.New[Feature]().
			Insert(GatewayCoreFeatures.UnsortedList()...).
			Insert(GatewayExtendedFeatures.UnsortedList()...).
			Insert(ReferenceGrantCoreFeatures.UnsortedList()...).
			Insert(HTTPRouteCoreFeatures.UnsortedList()...).
			Insert(HTTPRouteExtendedFeatures.UnsortedList()...).
			Insert(TLSRouteCoreFeatures.UnsortedList()...).
			Insert(MeshCoreFeatures.UnsortedList()...).
			Insert(MeshExtendedFeatures.UnsortedList()...).
			Insert(GRPCRouteCoreFeatures.UnsortedList()...)

	featureMap = map[FeatureName]Feature{}
)

func init() {
	for _, feature := range AllFeatures.UnsortedList() {
		featureMap[feature.Name] = feature
	}
}

// -----------------------------------------------------------------------------
// Features - Helpers
// -----------------------------------------------------------------------------

// SetsToNamesSet merges multiple sets of features into a single one and returns it.
func SetsToNamesSet(featuresSets ...sets.Set[Feature]) sets.Set[FeatureName] {
	res := sets.Set[FeatureName]{}
	for _, set := range featuresSets {
		for _, feature := range set.UnsortedList() {
			res.Insert(feature.Name)
		}
	}
	return res
}

// GetFeature returns the feature with the given name.
func GetFeature(name FeatureName) Feature {
	return featureMap[name]
}
