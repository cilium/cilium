// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"os"
	"strings"
	"testing"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/pkg/features"

	"github.com/cilium/cilium/pkg/testutils"
)

var (
	usableNetworkAddressesEnv   = "GATEWAY_API_CONFORMANCE_USABLE_NETWORK_ADDRESSES"
	unusableNetworkAddressesEnv = "GATEWAY_API_CONFORMANCE_UNUSABLE_NETWORK_ADDRESSES"
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
	var skipTests []string
	options := conformance.DefaultOptions(t)
	var usableNetworkAddresses []v1.GatewayAddress
	var unusableNetworkAddresses []v1.GatewayAddress
	usableAddresses := os.Getenv(usableNetworkAddressesEnv)
	if usableAddresses == "" {
		t.Logf("Set %s to run this test", features.SupportGatewayStaticAddresses)
		skipTests = append(skipTests, string(features.SupportGatewayStaticAddresses))
	} else {
		var addressType = v1.IPAddressType
		for _, value := range strings.Split(usableAddresses, ",") {
			usableNetworkAddresses = append(usableNetworkAddresses, v1.GatewayAddress{
				Type:  &addressType,
				Value: value,
			})
		}
	}
	unusableAddresses := os.Getenv(unusableNetworkAddressesEnv)
	if unusableAddresses == "" {
		t.Logf("Set %s to run this test", features.SupportGatewayStaticAddresses)
		skipTests = append(skipTests, string(features.SupportGatewayStaticAddresses))
	} else {
		var addressType = v1.IPAddressType
		for _, value := range strings.Split(unusableAddresses, ",") {
			unusableNetworkAddresses = append(unusableNetworkAddresses, v1.GatewayAddress{
				Type:  &addressType,
				Value: value,
			})
		}
	}
	options.UnusableNetworkAddresses = unusableNetworkAddresses
	options.UsableNetworkAddresses = usableNetworkAddresses
	options.SkipTests = append(options.SkipTests, skipTests...)
	conformance.RunConformanceWithOptions(t, options)
}
