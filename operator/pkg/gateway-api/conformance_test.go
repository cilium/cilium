// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	"github.com/cilium/cilium/pkg/testutils"
)

// TestConformance runs the conformance tests for Gateway API
// Adapted from https://github.com/kubernetes-sigs/gateway-api/blob/v0.5.1/conformance/conformance_test.go
// Some features are not supported by Cilium (e.g. v1alpha2 APIs, ReferenceGrant), so we skip them.
// This test should be adjusted as new features are added to the Gateway API.
//
// The below command can be used to run the conformance tests locally, you can also run directly from
// IDEs (e.g. Goland, VSCode) with the same settings.
//
//	GATEWAY_API_CONFORMANCE_TESTS=1 go test -v ./operator/pkg/gateway-api --gateway-class cilium --debug -test.run "TestConformance"
//
// You can also pass -test.run to run a specific test
//
//	GATEWAY_API_CONFORMANCE_TESTS=1 go test -v ./operator/pkg/gateway-api --gateway-class cilium --debug -test.run "TestConformance/HTTPRouteDisallowedKind"
func TestConformance(t *testing.T) {
	testutils.GatewayAPIConformanceTest(t)

	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("Error loading Kubernetes config: %v", err)
	}
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatalf("Error initializing Kubernetes c: %v", err)
	}
	_ = v1alpha2.AddToScheme(c.Scheme())
	_ = v1beta1.AddToScheme(c.Scheme())

	t.Logf("Running conformance tests with %s GatewayClass", *flags.GatewayClassName)

	cSuite := suite.New(suite.Options{
		Client:               c,
		GatewayClassName:     *flags.GatewayClassName,
		Debug:                *flags.ShowDebug,
		CleanupBaseResources: *flags.CleanupBaseResources,
		SupportedFeatures: []suite.SupportedFeature{
			suite.SupportReferenceGrant,
			suite.SupportHTTPRouteQueryParamMatching, // Extended conformance
		},
	})
	cSuite.Setup(t)
	cSuite.Run(t, tests.ConformanceTests)
}
