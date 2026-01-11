// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

const (
	// Indexes HTTPRoutes by all the backend Services referenced in the object.
	BackendServiceHTTPRouteIndex = "BackendServiceHTTPRouteIndex"

	// Indexes HTTPRoutes by all the backend ServiceImports referenced in the object.
	BackendServiceImportHTTPRouteIndex = "BackendServiceImportHTTPRouteIndex"

	// Indexes HTTPRoutes by all the Gateway parents referenced in the object.
	GatewayHTTPRouteIndex = "gatewayHTTPRouteIndex"

	// Indexes Gateways and records if the Gateway is relevant for Cilium.
	ImplementationGatewayIndex = "implementationGatewayIndex"

	// Indexes TLSRoutes by all the backend Services referenced in the object.
	BackendServiceTLSRouteIndex = "backendServiceTLSRouteIndex"

	// Indexes TLSRoutes by all the Gateway parents referenced in the object.
	GatewayTLSRouteIndex = "gatewayTLSRouteIndex"

	// Indexes GRPCRoutes by all the backend Services referenced in the object.
	BackendServiceGRPCRouteIndex = "backendServiceGRPCRouteIndex"

	// Indexes GRPCRoutes by all the Gateway parents referenced in the object.
	GatewayGRPCRouteIndex = "gatewayGRPCRouteIndex"

	// Indexes BackendTLSPolicies by all the ConfigMaps referenced in the object.
	BackendTLSPolicyConfigMapIndex = "backendTLSPolicyConfigMaps"

	// Indexes GAMMA HTTPRoutes by all the GAMMA parents of that HTTPRoute.
	// This is then be used by the Service reconciler to only retrieve any HTTPRoutes that have that specific
	// Service as a parent.
	GammaHTTPRouteParentRefsIndex = "gammaHTTPRouteParentRefs"

	// Indexes GAMMA GRPCRoutes by all the GAMMA parents of that GRPCRoute.
	// This is then be used by the Service reconciler to only retrieve any GRPCRoutes that have that specific
	// Service as a parent.
	GammaGRPCRouteParentRefsIndex = "gammaGRPCRouteParentRefs"
)
