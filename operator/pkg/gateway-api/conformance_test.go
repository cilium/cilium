// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	"github.com/cilium/cilium/pkg/testutils"
)

// TestConformance runs the conformance tests for Gateway API
// Adapted from https://github.com/kubernetes-sigs/gateway-api/blob/v0.6.1/conformance/conformance_test.go
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

	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("Error loading Kubernetes config: %v", err)
	}
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatalf("Error initializing Kubernetes client: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("Error initializing Kubernetes REST client: %v", err)
	}

	_ = v1alpha2.AddToScheme(c.Scheme())
	_ = v1beta1.AddToScheme(c.Scheme())
	_ = v1.AddToScheme(c.Scheme())

	supportedFeatures := suite.ParseSupportedFeatures(*flags.SupportedFeatures)
	exemptFeatures := suite.ParseSupportedFeatures(*flags.ExemptFeatures)
	skipTests := suite.ParseSkipTests(*flags.SkipTests)
	namespaceLabels := suite.ParseKeyValuePairs(*flags.NamespaceLabels)

	t.Logf("Running conformance tests with %s GatewayClass\n cleanup: %t\n debug: %t\n enable all features: %t \n supported features: [%v]\n exempt features: [%v]",
		*flags.GatewayClassName, *flags.CleanupBaseResources, *flags.ShowDebug, *flags.EnableAllSupportedFeatures, *flags.SupportedFeatures, *flags.ExemptFeatures)

	cSuite := suite.New(suite.Options{
		Client:     c,
		RestConfig: cfg,
		// This clientset is needed in addition to the client only because
		// controller-runtime client doesn't support non CRUD sub-resources yet (https://github.com/kubernetes-sigs/controller-runtime/issues/452).
		Clientset:                  clientset,
		GatewayClassName:           *flags.GatewayClassName,
		Debug:                      *flags.ShowDebug,
		CleanupBaseResources:       *flags.CleanupBaseResources,
		SupportedFeatures:          supportedFeatures,
		ExemptFeatures:             exemptFeatures,
		EnableAllSupportedFeatures: *flags.EnableAllSupportedFeatures,
		NamespaceLabels:            namespaceLabels,
		SkipTests:                  skipTests,
	})
	cSuite.Setup(t)
	cSuite.Run(t, tests.ConformanceTests)
}
