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

package suite

import "k8s.io/apimachinery/pkg/util/sets"

// -----------------------------------------------------------------------------
// Features - Types
// -----------------------------------------------------------------------------

// SupportedFeature allows opting in to additional conformance tests at an
// individual feature granularity.
type SupportedFeature string

// -----------------------------------------------------------------------------
// Features - Standard (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for ReferenceGrant (core conformance).
	// Opting out of this requires an implementation to have clearly implemented
	// and documented equivalent safeguards.
	SupportReferenceGrant SupportedFeature = "ReferenceGrant"
	// This option indicates support for Gateway (core conformance).
	// Opting out of this is allowed only for GAMMA-only implementations
	SupportGateway SupportedFeature = "Gateway"
)

// StandardCoreFeatures are the features that are required to be conformant with
// the Core API features (e.g. GatewayClass, Gateway, e.t.c.).
//
// TODO: we need clarity for standard vs experimental features.
// See: https://github.com/kubernetes-sigs/gateway-api/issues/1891
var StandardCoreFeatures = sets.New(
	SupportReferenceGrant,
	SupportGateway,
)

// -----------------------------------------------------------------------------
// Features - Standard (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates GatewayClass will update the observedGeneration in
	// it's conditions when reconciling (extended conformance).
	//
	// NOTE: we intend to make this core and require implementations to do it
	//       as we expect this is something every implementation should be able
	//       to do and it's ideal behavior.
	//
	//       See: https://github.com/kubernetes-sigs/gateway-api/issues/1780
	SupportGatewayClassObservedGenerationBump SupportedFeature = "GatewayClassObservedGenerationBump"
)

// StandardExtendedFeatures are extra generic features that implementations may
// choose to support as an opt-in.
//
// TODO: we need clarity for standard vs experimental features.
// See: https://github.com/kubernetes-sigs/gateway-api/issues/1891
var StandardExtendedFeatures = sets.New(
	SupportGatewayClassObservedGenerationBump,
).Insert(StandardCoreFeatures.UnsortedList()...)

// -----------------------------------------------------------------------------
// Features - Experimental (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for Destination Port matching.
	SupportRouteDestinationPortMatching SupportedFeature = "RouteDestinationPortMatching"
)

// ExperimentalExtendedFeatures are extra generic features that are currently
// only available in our experimental release channel, and at an extended
// support level.
//
// TODO: we need clarity for standard vs experimental features.
// See: https://github.com/kubernetes-sigs/gateway-api/issues/1891
var ExperimentalExtendedFeatures = sets.New(
	SupportRouteDestinationPortMatching,
)

// -----------------------------------------------------------------------------
// Features - HTTPRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for HTTPRoute
	SupportHTTPRoute SupportedFeature = "HTTPRoute"
)

// HTTPCoreFeatures includes all SupportedFeatures needed to be conformant with
// the HTTPRoute.
var HTTPCoreFeatures = sets.New(
	SupportHTTPRoute,
)

// -----------------------------------------------------------------------------
// Features - HTTPRoute Conformance (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for HTTPRoute query param matching (extended conformance).
	SupportHTTPRouteQueryParamMatching SupportedFeature = "HTTPRouteQueryParamMatching"

	// This option indicates support for HTTPRoute method matching (extended conformance).
	SupportHTTPRouteMethodMatching SupportedFeature = "HTTPRouteMethodMatching"

	// This option indicates support for HTTPRoute response header modification (extended conformance).
	SupportHTTPResponseHeaderModification SupportedFeature = "HTTPResponseHeaderModification"

	// This option indicates support for HTTPRoute port redirect (extended conformance).
	SupportHTTPRoutePortRedirect SupportedFeature = "HTTPRoutePortRedirect"

	// This option indicates support for HTTPRoute scheme redirect (extended conformance).
	SupportHTTPRouteSchemeRedirect SupportedFeature = "HTTPRouteSchemeRedirect"

	// This option indicates support for HTTPRoute path redirect (experimental conformance).
	SupportHTTPRoutePathRedirect SupportedFeature = "HTTPRoutePathRedirect"

	// This option indicates support for HTTPRoute host rewrite (experimental conformance)
	SupportHTTPRouteHostRewrite SupportedFeature = "HTTPRouteHostRewrite"

	// This option indicates support for HTTPRoute path rewrite (experimental conformance)
	SupportHTTPRoutePathRewrite SupportedFeature = "HTTPRoutePathRewrite"

	// This option indicates support for HTTPRoute request mirror (extended conformance).
	SupportHTTPRouteRequestMirror SupportedFeature = "HTTPRouteRequestMirror"
)

// HTTPExtendedFeatures includes all the supported features for HTTPRoute
// conformance and can be used to opt-in to run all HTTPRoute tests, including
// extended features.
var HTTPExtendedFeatures = sets.New(
	SupportHTTPRouteQueryParamMatching,
	SupportHTTPRouteMethodMatching,
	SupportHTTPResponseHeaderModification,
	SupportHTTPRoutePortRedirect,
	SupportHTTPRouteSchemeRedirect,
	SupportHTTPRoutePathRedirect,
	SupportHTTPRouteHostRewrite,
	SupportHTTPRoutePathRewrite,
	SupportHTTPRouteRequestMirror,
).Insert(HTTPCoreFeatures.UnsortedList()...)

// -----------------------------------------------------------------------------
// Features - TLSRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for TLSRoute
	SupportTLSRoute SupportedFeature = "TLSRoute"
)

// TLSCoreFeatures includes all the supported features for the TLSRoute API at
// a Core level of support.
var TLSCoreFeatures = sets.New(
	SupportTLSRoute,
)

// -----------------------------------------------------------------------------
// Features - Mesh Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates general support for service mesh
	SupportMesh SupportedFeature = "Mesh"
)

// MeshCoreFeatures includes all the supported features for the service mesh at
// a Core level of support.
var MeshCoreFeatures = sets.New(
	SupportMesh,
)

// -----------------------------------------------------------------------------
// Features - Compilations
// -----------------------------------------------------------------------------

// AllFeatures contains all the supported features and can be used to run all
// conformance tests with `all-features` flag.
//
// NOTE: as new feature sets are added they should be inserted into this set.
var AllFeatures = sets.New[SupportedFeature]().
	Insert(StandardExtendedFeatures.UnsortedList()...).
	Insert(ExperimentalExtendedFeatures.UnsortedList()...).
	Insert(HTTPExtendedFeatures.UnsortedList()...).
	Insert(TLSCoreFeatures.UnsortedList()...).
	Insert(MeshCoreFeatures.UnsortedList()...)
