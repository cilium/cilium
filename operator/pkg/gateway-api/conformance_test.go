// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"sigs.k8s.io/gateway-api/conformance"

	"github.com/cilium/cilium/pkg/testutils"
)

// TestConformance runs the conformance tests for Gateway API
// Adapted from https://github.com/kubernetes-sigs/gateway-api/blob/main/conformance/conformance_test.go
// Some features are not supported by Cilium, so we skip them.
// This test should be adjusted as new features are added to the Gateway API.
//
// The below command can be used to run the conformance tests locally, you can also run directly from
// IDEs (e.g. Goland, VSCode) with the same settings.
//
//	GATEWAY_API_CONFORMANCE_TESTS=1 go test -v ./operator/pkg/gateway-api \
//		--gateway-class cilium \
//		--supported-features ReferenceGrant,TLSRoute,HTTPRouteQueryParamMatching,HTTPRouteMethodMatching,HTTPResponseHeaderModification,RouteDestinationPortMatching,GatewayClassObservedGenerationBump \
//		--debug -test.run "TestConformance"
//
// You can also pass -test.run to run a specific test
//
//	GATEWAY_API_CONFORMANCE_TESTS=1 go test -v ./operator/pkg/gateway-api \
//		--gateway-class cilium \
//		--supported-features ReferenceGrant,TLSRoute,HTTPRouteQueryParamMatching,HTTPRouteMethodMatching,HTTPResponseHeaderModification,RouteDestinationPortMatching,GatewayClassObservedGenerationBump \
//		--debug -test.run "TestConformance/HTTPRouteDisallowedKind"
func TestConformance(t *testing.T) {
	testutils.GatewayAPIConformanceTest(t)

	conformance.RunConformance(t)
}
