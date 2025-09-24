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
	// This option indicates mesh support for HTTPRoute path rewrite (extended conformance)
	SupportMeshHTTPRouteRewritePath FeatureName = "MeshHTTPRouteRewritePath"
	// This option indicates mesh support for HTTPRoute scheme redirect (extended conformance)
	SupportMeshHTTPRouteSchemeRedirect FeatureName = "MeshHTTPRouteSchemeRedirect"
	// This option indicates mesh support for HTTPRoute port redirect (extended conformance)
	SupportMeshHTTPRouteRedirectPort FeatureName = "MeshHTTPRouteRedirectPort"
	// This option indicates mesh support for HTTPRoute path redirect (extended conformance)
	SupportMeshHTTPRouteRedirectPath FeatureName = "MeshHTTPRouteRedirectPath"
	// This option indicates support for HTTPRoute backend request header modification
	SupportMeshHTTPRouteBackendRequestHeaderModification FeatureName = "MeshHTTPRouteBackendRequestHeaderModification"
	// This option indicates mesh support for HTTPRoute query param matching (extended conformance).
	SupportMeshHTTPRouteQueryParamMatching FeatureName = "MeshHTTPRouteQueryParamMatching"
	// This option indicates support for the name field in the HTTPRouteRule (extended conformance)
	SupportMeshHTTPRouteNamedRouteRule FeatureName = "MeshHTTPRouteNamedRouteRule"
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

	// MeshHTTPRouteRewritePath contains metadata for the MeshHTTPRouteRewritePath feature.
	MeshHTTPRouteRewritePath = Feature{
		Name:    SupportMeshHTTPRouteRewritePath,
		Channel: FeatureChannelStandard,
	}

	// MeshHTTPRouteSchemeRedirect contains metadata for the MeshHTTPRouteSchemeRedirect feature.
	MeshHTTPRouteSchemeRedirect = Feature{
		Name:    SupportMeshHTTPRouteSchemeRedirect,
		Channel: FeatureChannelStandard,
	}

	// MeshHTTPRouteRedirectPort contains metadata for the MeshHTTPRouteRedirectPort feature.
	MeshHTTPRouteRedirectPort = Feature{
		Name:    SupportMeshHTTPRouteRedirectPort,
		Channel: FeatureChannelStandard,
	}

	// MeshHTTPRouteRedirectPath contains metadata for the MeshHTTPRouteRedirectPath feature.
	MeshHTTPRouteRedirectPath = Feature{
		Name:    SupportMeshHTTPRouteRedirectPath,
		Channel: FeatureChannelStandard,
	}

	// MeshHTTPRouteRedirectPath contains metadata for the MeshHTTPRouteRedirectPath feature.
	MeshHTTPRouteBackendRequestHeaderModification = Feature{
		Name:    SupportMeshHTTPRouteBackendRequestHeaderModification,
		Channel: FeatureChannelStandard,
	}

	// MeshHTTPRouteRedirectPath contains metadata for the MeshHTTPRouteRedirectPath feature.
	MeshHTTPRouteQueryParamMatching = Feature{
		Name:    SupportMeshHTTPRouteQueryParamMatching,
		Channel: FeatureChannelStandard,
	}

	// MeshHTTPRouteNamedRouteRule contains metadata for the MeshHTTPRouteNamedRouteRule feature.
	MeshHTTPRouteNamedRouteRule = Feature{
		Name:    SupportMeshHTTPRouteNamedRouteRule,
		Channel: FeatureChannelStandard,
	}
)

// MeshExtendedFeatures includes all the supported features for the service mesh at
// an Extended level of support.
var MeshExtendedFeatures = sets.New(
	MeshClusterIPMatchingFeature,
	MeshConsumerRouteFeature,
	MeshHTTPRouteRewritePath,
	MeshHTTPRouteSchemeRedirect,
	MeshHTTPRouteRedirectPort,
	MeshHTTPRouteRedirectPath,
	MeshHTTPRouteBackendRequestHeaderModification,
	MeshHTTPRouteQueryParamMatching,
	MeshHTTPRouteNamedRouteRule,
)
