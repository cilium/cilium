/*
Copyright 2024 The Kubernetes Authors.

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
// Features - TLSRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for TLSRoute
	SupportTLSRoute FeatureName = "TLSRoute"
)

// TLSRouteFeature contains metadata for the TLSRoute feature.
var TLSRouteFeature = Feature{
	Name:    SupportTLSRoute,
	Channel: FeatureChannelExperimental,
}

// TLSCoreFeatures includes all the supported features for the TLSRoute API at
// a Core level of support.
var TLSRouteCoreFeatures = sets.New(
	TLSRouteFeature,
)
