/*
Copyright The Kubernetes Authors.

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
// Features - TCPRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// SupportTCPRoute option indicates support for TCPRoute.
	SupportTCPRoute FeatureName = "TCPRoute"
)

// TCPRouteFeature contains metadata for the TCPRoute feature.
var TCPRouteFeature = Feature{
	Name:    SupportTCPRoute,
	Channel: FeatureChannelStandard,
}

// TCPRouteExtendedFeatures includes all extended features for TCPRoute
// conformance and can be used to opt-in to run all TCPRoute extended feature
// tests. This does not include any Core Features.
var TCPRouteExtendedFeatures = sets.New(
	TCPRouteFeature,
)
