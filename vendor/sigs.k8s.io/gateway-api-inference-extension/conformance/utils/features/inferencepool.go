/*
Copyright 2026 The Kubernetes Authors.

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

import (
	"k8s.io/apimachinery/pkg/util/sets"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"
)

// -----------------------------------------------------------------------------
// Features - InferencePool Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for ReferenceGrant.
	SupportInferencePool gatewayfeatures.FeatureName = "SupportInferencePool"
)

// InferencePoolFeature contains metadata for the ReferenceGrant feature.
var InferencePoolFeature = gatewayfeatures.Feature{
	Name:    SupportInferencePool,
	Channel: gatewayfeatures.FeatureChannelStandard,
}

// InferencePoolCoreFeatures includes all SupportedFeatures needed to be
// conformant with the InferencePool resource.
var InferenceCoreFeatures = sets.New(
	gatewayfeatures.SupportGateway, // This is needed to ensure manifest gets applied during setup.
	gatewayfeatures.SupportHTTPRoute,
	SupportInferencePool,
)
