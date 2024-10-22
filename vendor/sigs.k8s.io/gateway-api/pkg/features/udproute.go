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

// -----------------------------------------------------------------------------
// Features - UDPRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for UDPRoute
	SupportUDPRoute FeatureName = "UDPRoute"
)

// UDPRouteFeature contains metadata for the UDPRoute feature.
var UDPRouteFeature = Feature{
	Name:    SupportUDPRoute,
	Channel: FeatureChannelExperimental,
}

// UDPRouteCoreFeatures includes all SupportedFeatures needed to be conformant with
// the UDPRoute resource.
var UDPRouteFeatures = map[FeatureName]Feature{
	SupportUDPRoute: UDPRouteFeature,
}
