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
// Features - GRPCRoute Conformance
// -----------------------------------------------------------------------------

const (
	// This option indicates general support for GRPCRoute.
	SupportGRPCRoute FeatureName = "GRPCRoute"
)

// GRPCRouteFeature contains metadata for the GRPCRoute feature.
var GRPCRouteFeature = Feature{
	Name:    SupportGRPCRoute,
	Channel: FeatureChannelStandard,
}

// GRPCRouteCoreFeatures includes all the supported features for GRPCRoute at
// a Core level of support.
var GRPCRouteCoreFeatures = sets.New(
	GRPCRouteFeature,
)
