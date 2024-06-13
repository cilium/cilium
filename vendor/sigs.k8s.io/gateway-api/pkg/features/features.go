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

// SupportedFeature allows opting in to additional conformance tests at an
// individual feature granularity.
type SupportedFeature string

// -----------------------------------------------------------------------------
// Features - Gateway Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for Gateway.
	// Opting out of this is allowed only for GAMMA-only implementations
	SupportGateway SupportedFeature = "Gateway"
)

// GatewayCoreFeatures are the features that are required to be conformant with
// the Gateway resource.
var GatewayCoreFeatures = sets.New(
	SupportGateway,
)

// -----------------------------------------------------------------------------
// Features - Gateway Conformance (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates that the Gateway can also use port 8080
	SupportGatewayPort8080 SupportedFeature = "GatewayPort8080"

	// SupportGatewayStaticAddresses option indicates that the Gateway is capable
	// of allocating pre-determined addresses, rather than dynamically having
	// addresses allocated for it.
	SupportGatewayStaticAddresses SupportedFeature = "GatewayStaticAddresses"

	// SupportGatewayHTTPListenerIsolation option indicates support for the isolation
	// of HTTP listeners.
	SupportGatewayHTTPListenerIsolation SupportedFeature = "GatewayHTTPListenerIsolation"
)

// GatewayExtendedFeatures are extra generic features that implementations may
// choose to support as an opt-in. This does not include any Core Features.
var GatewayExtendedFeatures = sets.New(
	SupportGatewayPort8080,
	SupportGatewayStaticAddresses,
	SupportGatewayHTTPListenerIsolation,
)

// -----------------------------------------------------------------------------
// Features - ReferenceGrant Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for ReferenceGrant.
	SupportReferenceGrant SupportedFeature = "ReferenceGrant"
)

// ReferenceGrantCoreFeatures includes all SupportedFeatures needed to be
// conformant with the ReferenceGrant resource.
var ReferenceGrantCoreFeatures = sets.New(
	SupportReferenceGrant,
)

// -----------------------------------------------------------------------------
// Features - HTTPRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for HTTPRoute
	SupportHTTPRoute SupportedFeature = "HTTPRoute"
)

// HTTPRouteCoreFeatures includes all SupportedFeatures needed to be conformant with
// the HTTPRoute resource.
var HTTPRouteCoreFeatures = sets.New(
	SupportHTTPRoute,
)

// -----------------------------------------------------------------------------
// Features - HTTPRoute Conformance (Extended)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for HTTPRoute backend request header modification
	SupportHTTPRouteBackendRequestHeaderModification SupportedFeature = "HTTPRouteBackendRequestHeaderModification"

	// This option indicates support for HTTPRoute query param matching (extended conformance).
	SupportHTTPRouteQueryParamMatching SupportedFeature = "HTTPRouteQueryParamMatching"

	// This option indicates support for HTTPRoute method matching (extended conformance).
	SupportHTTPRouteMethodMatching SupportedFeature = "HTTPRouteMethodMatching"

	// This option indicates support for HTTPRoute response header modification (extended conformance).
	SupportHTTPRouteResponseHeaderModification SupportedFeature = "HTTPRouteResponseHeaderModification"

	// This option indicates support for HTTPRoute port redirect (extended conformance).
	SupportHTTPRoutePortRedirect SupportedFeature = "HTTPRoutePortRedirect"

	// This option indicates support for HTTPRoute scheme redirect (extended conformance).
	SupportHTTPRouteSchemeRedirect SupportedFeature = "HTTPRouteSchemeRedirect"

	// This option indicates support for HTTPRoute path redirect (extended conformance).
	SupportHTTPRoutePathRedirect SupportedFeature = "HTTPRoutePathRedirect"

	// This option indicates support for HTTPRoute host rewrite (extended conformance)
	SupportHTTPRouteHostRewrite SupportedFeature = "HTTPRouteHostRewrite"

	// This option indicates support for HTTPRoute path rewrite (extended conformance)
	SupportHTTPRoutePathRewrite SupportedFeature = "HTTPRoutePathRewrite"

	// This option indicates support for HTTPRoute request mirror (extended conformance).
	SupportHTTPRouteRequestMirror SupportedFeature = "HTTPRouteRequestMirror"

	// This option indicates support for multiple RequestMirror filters within the same HTTPRoute rule (extended conformance).
	SupportHTTPRouteRequestMultipleMirrors SupportedFeature = "HTTPRouteRequestMultipleMirrors"

	// This option indicates support for HTTPRoute request timeouts (extended conformance).
	SupportHTTPRouteRequestTimeout SupportedFeature = "HTTPRouteRequestTimeout"

	// This option indicates support for HTTPRoute backendRequest timeouts (extended conformance).
	SupportHTTPRouteBackendTimeout SupportedFeature = "HTTPRouteBackendTimeout"

	// This option indicates support for HTTPRoute parentRef port (extended conformance).
	SupportHTTPRouteParentRefPort SupportedFeature = "HTTPRouteParentRefPort"
)

// HTTPRouteExtendedFeatures includes all extended features for HTTPRoute
// conformance and can be used to opt-in to run all HTTPRoute extended features tests.
// This does not include any Core Features.
var HTTPRouteExtendedFeatures = sets.New(
	SupportHTTPRouteQueryParamMatching,
	SupportHTTPRouteMethodMatching,
	SupportHTTPRouteResponseHeaderModification,
	SupportHTTPRoutePortRedirect,
	SupportHTTPRouteSchemeRedirect,
	SupportHTTPRoutePathRedirect,
	SupportHTTPRouteHostRewrite,
	SupportHTTPRoutePathRewrite,
	SupportHTTPRouteRequestMirror,
	SupportHTTPRouteRequestMultipleMirrors,
	SupportHTTPRouteRequestTimeout,
	SupportHTTPRouteBackendTimeout,
	SupportHTTPRouteParentRefPort,
	SupportHTTPRouteBackendRequestHeaderModification,
)

// -----------------------------------------------------------------------------
// Features - HTTPRoute Conformance (Experimental)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for Destination Port matching.
	SupportHTTPRouteDestinationPortMatching SupportedFeature = "HTTPRouteDestinationPortMatching"

	// This option indicates support for HTTPRoute with a backendref with an appProtocol 'kubernetes.io/h2c'
	SupportHTTPRouteBackendProtocolH2C SupportedFeature = "HTTPRouteBackendProtocolH2C"

	// This option indicates support for HTTPRoute with a backendref with an appProtoocol 'kubernetes.io/ws'
	SupportHTTPRouteBackendProtocolWebSocket SupportedFeature = "HTTPRouteBackendProtocolWebSocket"
)

// HTTPRouteExperimentalFeatures includes all the supported experimental features, currently only
// available in our experimental release channel.
// Implementations have the flexibility to opt-in for either specific features or the entire set.
var HTTPRouteExperimentalFeatures = sets.New(
	SupportHTTPRouteDestinationPortMatching,
	SupportHTTPRouteBackendProtocolH2C,
	SupportHTTPRouteBackendProtocolWebSocket,
)

// -----------------------------------------------------------------------------
// Features - TLSRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for TLSRoute
	SupportTLSRoute SupportedFeature = "TLSRoute"
)

// TLSCoreFeatures includes all the supported features for the TLSRoute API at
// a Core level of support.
var TLSRouteCoreFeatures = sets.New(
	SupportTLSRoute,
)

// -----------------------------------------------------------------------------
// Features - UDPRoute Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates support for UDPRoute
	SupportUDPRoute SupportedFeature = "UDPRoute"
)

// UDPRouteCoreFeatures includes all SupportedFeatures needed to be conformant with
// the UDPRoute resource.
var UDPRouteFeatures = sets.New(
	SupportUDPRoute,
)

// -----------------------------------------------------------------------------
// Features - Mesh Conformance (Core)
// -----------------------------------------------------------------------------

const (
	// This option indicates general support for service mesh
	SupportMesh SupportedFeature = "Mesh"
	// This option indicates support for matching Service traffic specifically by Cluster IP rather than other mechanisms.
	SupportMeshClusterIPMatching SupportedFeature = "MeshClusterIPMatching"
	// This option indicates support for "consumer" routes, where a namespace creates a route for a service in another namespace.
	SupportMeshConsumerRoute SupportedFeature = "MeshConsumerRoute"
)

// MeshCoreFeatures includes all the supported features for the service mesh at
// a Core level of support.
var MeshCoreFeatures = sets.New(
	SupportMesh,
)

// MeshExtendedFeatures includes all the supported features for the service mesh at
// an Extended level of support.
var MeshExtendedFeatures = sets.New(
	SupportMeshClusterIPMatching,
	SupportMeshConsumerRoute,
)

// -----------------------------------------------------------------------------
// Features - GRPCRoute Conformance
// -----------------------------------------------------------------------------

const (
	// This option indicates general support for service mesh
	SupportGRPCRoute SupportedFeature = "GRPCRoute"
)

// GRPCRouteCoreFeatures includes all the supported features for GRPCRoute at
// a Core level of support.
var GRPCRouteCoreFeatures = sets.New(
	SupportGRPCRoute,
)

// -----------------------------------------------------------------------------
// Features - Compilations
// -----------------------------------------------------------------------------

// AllFeatures contains all the supported features and can be used to run all
// conformance tests with `all-features` flag.
//
// NOTE: as new feature sets are added they should be inserted into this set.
var AllFeatures = sets.New[SupportedFeature]().
	Insert(GatewayCoreFeatures.UnsortedList()...).
	Insert(GatewayExtendedFeatures.UnsortedList()...).
	Insert(ReferenceGrantCoreFeatures.UnsortedList()...).
	Insert(HTTPRouteCoreFeatures.UnsortedList()...).
	Insert(HTTPRouteExtendedFeatures.UnsortedList()...).
	Insert(HTTPRouteExperimentalFeatures.UnsortedList()...).
	Insert(TLSRouteCoreFeatures.UnsortedList()...).
	Insert(MeshCoreFeatures.UnsortedList()...).
	Insert(MeshExtendedFeatures.UnsortedList()...).
	Insert(GRPCRouteCoreFeatures.UnsortedList()...)
