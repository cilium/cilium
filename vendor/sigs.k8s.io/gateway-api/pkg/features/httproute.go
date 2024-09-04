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
// Features - HTTPRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for HTTPRoute
	SupportHTTPRoute FeatureName = "HTTPRoute"
)

// HTTPRouteFeature contains metadata for the HTTPRoute feature.
var HTTPRouteFeature = Feature{
	Name:    SupportHTTPRoute,
	Channel: FeatureChannelStandard,
}

// HTTPRouteCoreFeatures includes all SupportedFeatures needed to be conformant with
// the HTTPRoute resource.
var HTTPRouteCoreFeatures = sets.New(
	HTTPRouteFeature,
)

// -----------------------------------------------------------------------------
// Features - HTTPRoute Conformance (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for Destination Port matching.
	SupportHTTPRouteDestinationPortMatching FeatureName = "HTTPRouteDestinationPortMatching"

	// This option indicates support for HTTPRoute backend request header modification
	SupportHTTPRouteBackendRequestHeaderModification FeatureName = "HTTPRouteBackendRequestHeaderModification"

	// This option indicates support for HTTPRoute query param matching (extended conformance).
	SupportHTTPRouteQueryParamMatching FeatureName = "HTTPRouteQueryParamMatching"

	// This option indicates support for HTTPRoute method matching (extended conformance).
	SupportHTTPRouteMethodMatching FeatureName = "HTTPRouteMethodMatching"

	// This option indicates support for HTTPRoute response header modification (extended conformance).
	SupportHTTPRouteResponseHeaderModification FeatureName = "HTTPRouteResponseHeaderModification"

	// This option indicates support for HTTPRoute port redirect (extended conformance).
	SupportHTTPRoutePortRedirect FeatureName = "HTTPRoutePortRedirect"

	// This option indicates support for HTTPRoute scheme redirect (extended conformance).
	SupportHTTPRouteSchemeRedirect FeatureName = "HTTPRouteSchemeRedirect"

	// This option indicates support for HTTPRoute path redirect (extended conformance).
	SupportHTTPRoutePathRedirect FeatureName = "HTTPRoutePathRedirect"

	// This option indicates support for HTTPRoute host rewrite (extended conformance)
	SupportHTTPRouteHostRewrite FeatureName = "HTTPRouteHostRewrite"

	// This option indicates support for HTTPRoute path rewrite (extended conformance)
	SupportHTTPRoutePathRewrite FeatureName = "HTTPRoutePathRewrite"

	// This option indicates support for HTTPRoute request mirror (extended conformance).
	SupportHTTPRouteRequestMirror FeatureName = "HTTPRouteRequestMirror"

	// This option indicates support for multiple RequestMirror filters within the same HTTPRoute rule (extended conformance).
	SupportHTTPRouteRequestMultipleMirrors FeatureName = "HTTPRouteRequestMultipleMirrors"

	// This option indicates support for HTTPRoute request timeouts (extended conformance).
	SupportHTTPRouteRequestTimeout FeatureName = "HTTPRouteRequestTimeout"

	// This option indicates support for HTTPRoute backendRequest timeouts (extended conformance).
	SupportHTTPRouteBackendTimeout FeatureName = "HTTPRouteBackendTimeout"

	// This option indicates support for HTTPRoute parentRef port (extended conformance).
	SupportHTTPRouteParentRefPort FeatureName = "HTTPRouteParentRefPort"

	// This option indicates support for HTTPRoute with a backendref with an appProtocol 'kubernetes.io/h2c' (extended conformance)
	SupportHTTPRouteBackendProtocolH2C FeatureName = "HTTPRouteBackendProtocolH2C"

	// This option indicates support for HTTPRoute with a backendref with an appProtoocol 'kubernetes.io/ws' (extended conformance)
	SupportHTTPRouteBackendProtocolWebSocket FeatureName = "HTTPRouteBackendProtocolWebSocket"
)

var (
	// HTTPRouteDestinationPortMatchingFeature contains metadata for the HTTPRouteDestinationPortMatching feature.
	HTTPRouteDestinationPortMatchingFeature = Feature{
		Name:    SupportHTTPRouteDestinationPortMatching,
		Channel: FeatureChannelExperimental,
	}
	// HTTPRouteBackendRequestHeaderModificationFeature contains metadata for the HTTPRouteBackendRequestHeaderModification feature.
	HTTPRouteBackendRequestHeaderModificationFeature = Feature{
		Name:    SupportHTTPRouteBackendRequestHeaderModification,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteQueryParamMatchingFeature contains metadata for the HTTPRouteQueryParamMatching feature.
	HTTPRouteQueryParamMatchingFeature = Feature{
		Name:    SupportHTTPRouteQueryParamMatching,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteMethodMatchingFeature contains metadata for the HTTPRouteMethodMatching feature.
	HTTPRouteMethodMatchingFeature = Feature{
		Name:    SupportHTTPRouteMethodMatching,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteResponseHeaderModificationFeature contains metadata for the HTTPRouteResponseHeaderModification feature.
	HTTPRouteResponseHeaderModificationFeature = Feature{
		Name:    SupportHTTPRouteResponseHeaderModification,
		Channel: FeatureChannelStandard,
	}
	// HTTPRoutePortRedirectFeature contains metadata for the HTTPRoutePortRedirect feature.
	HTTPRoutePortRedirectFeature = Feature{
		Name:    SupportHTTPRoutePortRedirect,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteSchemeRedirectFeature contains metadata for the HTTPRouteSchemeRedirect feature.
	HTTPRouteSchemeRedirectFeature = Feature{
		Name:    SupportHTTPRouteSchemeRedirect,
		Channel: FeatureChannelStandard,
	}
	// HTTPRoutePathRedirectFeature contains metadata for the HTTPRoutePathRedirect feature.
	HTTPRoutePathRedirectFeature = Feature{
		Name:    SupportHTTPRoutePathRedirect,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteHostRewriteFeature contains metadata for the HTTPRouteHostRewrite feature.
	HTTPRouteHostRewriteFeature = Feature{
		Name:    SupportHTTPRouteHostRewrite,
		Channel: FeatureChannelStandard,
	}
	// HTTPRoutePathRewriteFeature contains metadata for the HTTPRoutePathRewrite feature.
	HTTPRoutePathRewriteFeature = Feature{
		Name:    SupportHTTPRoutePathRewrite,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteRequestMirrorFeature contains metadata for the HTTPRouteRequestMirror feature.
	HTTPRouteRequestMirrorFeature = Feature{
		Name:    SupportHTTPRouteRequestMirror,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteRequestMultipleMirrorsFeature contains metadata for the HTTPRouteRequestMultipleMirrors feature.
	HTTPRouteRequestMultipleMirrorsFeature = Feature{
		Name:    SupportHTTPRouteRequestMultipleMirrors,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteRequestTimeoutFeature contains metadata for the HTTPRouteRequestTimeout feature.
	HTTPRouteRequestTimeoutFeature = Feature{
		Name:    SupportHTTPRouteRequestTimeout,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteBackendTimeoutFeature contains metadata for the HTTPRouteBackendTimeout feature.
	HTTPRouteBackendTimeoutFeature = Feature{
		Name:    SupportHTTPRouteBackendTimeout,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteParentRefPortFeature contains metadata for the HTTPRouteParentRefPort feature.
	HTTPRouteParentRefPortFeature = Feature{
		Name:    SupportHTTPRouteParentRefPort,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteBackendProtocolH2CFeature contains metadata for the HTTPRouteBackendProtocolH2C feature.
	HTTPRouteBackendProtocolH2CFeature = Feature{
		Name:    SupportHTTPRouteBackendProtocolH2C,
		Channel: FeatureChannelStandard,
	}
	// HTTPRouteBackendProtocolWebSocketFeature contains metadata for the HTTPRouteBackendProtocolWebSocket feature.
	HTTPRouteBackendProtocolWebSocketFeature = Feature{
		Name:    SupportHTTPRouteBackendProtocolWebSocket,
		Channel: FeatureChannelStandard,
	}
)

// HTTPRouteExtendedFeatures includes all extended features for HTTPRoute
// conformance and can be used to opt-in to run all HTTPRoute extended features tests.
// This does not include any Core Features.
var HTTPRouteExtendedFeatures = sets.New(
	HTTPRouteDestinationPortMatchingFeature,
	HTTPRouteBackendRequestHeaderModificationFeature,
	HTTPRouteQueryParamMatchingFeature,
	HTTPRouteMethodMatchingFeature,
	HTTPRouteResponseHeaderModificationFeature,
	HTTPRoutePortRedirectFeature,
	HTTPRouteSchemeRedirectFeature,
	HTTPRoutePathRedirectFeature,
	HTTPRouteHostRewriteFeature,
	HTTPRoutePathRewriteFeature,
	HTTPRouteRequestMirrorFeature,
	HTTPRouteRequestMultipleMirrorsFeature,
	HTTPRouteRequestTimeoutFeature,
	HTTPRouteBackendTimeoutFeature,
	HTTPRouteParentRefPortFeature,
	HTTPRouteBackendProtocolH2CFeature,
	HTTPRouteBackendProtocolWebSocketFeature,
)
