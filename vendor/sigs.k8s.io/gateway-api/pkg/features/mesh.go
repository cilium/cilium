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
// Features - Mesh Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates general support for service mesh
	SupportMesh FeatureName = "Mesh"
)

// MeshFeature contains metadata for the Mesh feature.
var MeshFeature = Feature{
	Name:    SupportMesh,
	Channel: FeatureChannelStandard,
}

// MeshCoreFeatures includes all the supported features for the service mesh at
// a Core level of support.
var MeshCoreFeatures = sets.New(
	MeshFeature,
)

// -----------------------------------------------------------------------------
// Features - Mesh Conformance (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for matching Service traffic specifically by Cluster IP rather than other mechanisms.
	SupportMeshClusterIPMatching FeatureName = "MeshClusterIPMatching"
	// This option indicates support for "consumer" routes, where a namespace creates a route for a service in another namespace.
	SupportMeshConsumerRoute FeatureName = "MeshConsumerRoute"
)

var (
	// MeshClusterIPMatchingFeature contains metadata for the MeshClusterIPMatching feature.
	MeshClusterIPMatchingFeature = Feature{
		Name:    SupportMeshClusterIPMatching,
		Channel: FeatureChannelStandard,
	}
	// MeshConsumerRouteFeature contains metadata for the MeshConsumerRoute feature.
	MeshConsumerRouteFeature = Feature{
		Name:    SupportMeshConsumerRoute,
		Channel: FeatureChannelStandard,
	}
)

// MeshExtendedFeatures includes all the supported features for the service mesh at
// an Extended level of support.
var MeshExtendedFeatures = sets.New(
	MeshClusterIPMatchingFeature,
	MeshConsumerRouteFeature,
)
