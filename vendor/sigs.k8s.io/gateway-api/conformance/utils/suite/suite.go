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

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

// SupportedFeature allows opting in to additional conformance tests at an
// individual feature granularity.
type SupportedFeature string

const (
	// This option indicates support for ReferenceGrant (core conformance).
	// Opting out of this requires an implementation to have clearly implemented
	// and documented equivalent safeguards.
	SupportReferenceGrant SupportedFeature = "ReferenceGrant"

	// This option indicates support for TLSRoute (extended conformance).
	SupportTLSRoute SupportedFeature = "TLSRoute"

	// This option indicates support for HTTPRoute query param matching (extended conformance).
	SupportHTTPRouteQueryParamMatching SupportedFeature = "HTTPRouteQueryParamMatching"

	// This option indicates support for HTTPRoute method matching (extended conformance).
	SupportHTTPRouteMethodMatching SupportedFeature = "HTTPRouteMethodMatching"

	// This option indicates support for HTTPRoute response header modification (extended conformance).
	SupportHTTPResponseHeaderModification SupportedFeature = "HTTPResponseHeaderModification"

	// This option indicates support for Destination Port matching (extended conformance).
	SupportRouteDestinationPortMatching SupportedFeature = "RouteDestinationPortMatching"

	// This option indicates GatewayClass will update the observedGeneration in it's conditions when reconciling
	SupportGatewayClassObservedGenerationBump SupportedFeature = "GatewayClassObservedGenerationBump"
)

// StandardCoreFeatures are the features that are required to be conformant with
// the Core API features that are part of the Standard release channel.
var StandardCoreFeatures = map[SupportedFeature]bool{
	SupportReferenceGrant: true,
}

// ConformanceTestSuite defines the test suite used to run Gateway API
// conformance tests.
type ConformanceTestSuite struct {
	Client            client.Client
	RoundTripper      roundtripper.RoundTripper
	GatewayClassName  string
	ControllerName    string
	Debug             bool
	Cleanup           bool
	BaseManifests     string
	Applier           kubernetes.Applier
	SupportedFeatures map[SupportedFeature]bool
	TimeoutConfig     config.TimeoutConfig
}

// Options can be used to initialize a ConformanceTestSuite.
type Options struct {
	Client           client.Client
	GatewayClassName string
	Debug            bool
	RoundTripper     roundtripper.RoundTripper
	BaseManifests    string
	NamespaceLabels  map[string]string
	// ValidUniqueListenerPorts maps each listener port of each Gateway in the
	// manifests to a valid, unique port. There must be as many
	// ValidUniqueListenerPorts as there are listeners in the set of manifests.
	// For example, given two Gateways, each with 2 listeners, there should be
	// four ValidUniqueListenerPorts.
	// If empty or nil, ports are not modified.
	ValidUniqueListenerPorts []v1beta1.PortNumber

	// CleanupBaseResources indicates whether or not the base test
	// resources such as Gateways should be cleaned up after the run.
	CleanupBaseResources bool
	SupportedFeatures    map[SupportedFeature]bool
	TimeoutConfig        config.TimeoutConfig
}

// New returns a new ConformanceTestSuite.
func New(s Options) *ConformanceTestSuite {
	config.SetupTimeoutConfig(&s.TimeoutConfig)

	roundTripper := s.RoundTripper
	if roundTripper == nil {
		roundTripper = &roundtripper.DefaultRoundTripper{Debug: s.Debug, TimeoutConfig: s.TimeoutConfig}
	}

	if s.SupportedFeatures == nil {
		s.SupportedFeatures = StandardCoreFeatures
	} else {
		for feature, val := range StandardCoreFeatures {
			if _, ok := s.SupportedFeatures[feature]; !ok {
				s.SupportedFeatures[feature] = val
			}
		}
	}

	suite := &ConformanceTestSuite{
		Client:           s.Client,
		RoundTripper:     roundTripper,
		GatewayClassName: s.GatewayClassName,
		Debug:            s.Debug,
		Cleanup:          s.CleanupBaseResources,
		BaseManifests:    s.BaseManifests,
		Applier: kubernetes.Applier{
			NamespaceLabels:          s.NamespaceLabels,
			ValidUniqueListenerPorts: s.ValidUniqueListenerPorts,
		},
		SupportedFeatures: s.SupportedFeatures,
		TimeoutConfig:     s.TimeoutConfig,
	}

	// apply defaults
	if suite.BaseManifests == "" {
		suite.BaseManifests = "base/manifests.yaml"
	}

	return suite
}

// Setup ensures the base resources required for conformance tests are installed
// in the cluster. It also ensures that all relevant resources are ready.
func (suite *ConformanceTestSuite) Setup(t *testing.T) {
	t.Logf("Test Setup: Ensuring GatewayClass has been accepted")
	suite.ControllerName = kubernetes.GWCMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.GatewayClassName)

	suite.Applier.GatewayClass = suite.GatewayClassName
	suite.Applier.ControllerName = suite.ControllerName

	t.Logf("Test Setup: Applying base manifests")
	suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, suite.BaseManifests, suite.Cleanup)

	t.Logf("Test Setup: Applying programmatic resources")
	secret := kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-web-backend", "certificate", []string{"*"})
	suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)
	secret = kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-infra", "tls-validity-checks-certificate", []string{"*"})
	suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)

	t.Logf("Test Setup: Ensuring Gateways and Pods from base manifests are ready")
	namespaces := []string{
		"gateway-conformance-infra",
		"gateway-conformance-app-backend",
		"gateway-conformance-web-backend",
	}
	kubernetes.NamespacesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, namespaces)
}

// Run runs the provided set of conformance tests.
func (suite *ConformanceTestSuite) Run(t *testing.T, tests []ConformanceTest) {
	for _, test := range tests {
		t.Run(test.ShortName, func(t *testing.T) {
			test.Run(t, suite)
		})
	}
}

// ConformanceTest is used to define each individual conformance test.
type ConformanceTest struct {
	ShortName   string
	Description string
	Features    []SupportedFeature
	Manifests   []string
	Slow        bool
	Parallel    bool
	Test        func(*testing.T, *ConformanceTestSuite)
}

// Run runs an individual tests, applying and cleaning up the required manifests
// before calling the Test function.
func (test *ConformanceTest) Run(t *testing.T, suite *ConformanceTestSuite) {
	if test.Parallel {
		t.Parallel()
	}

	// Check that all features exercised by the test have been opted into by
	// the suite.
	for _, feature := range test.Features {
		if supported, ok := suite.SupportedFeatures[feature]; !ok || !supported {
			t.Skipf("Skipping %s: suite does not support %s", test.ShortName, feature)
		}
	}

	for _, manifestLocation := range test.Manifests {
		t.Logf("Applying %s", manifestLocation)
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, manifestLocation, true)
	}

	test.Test(t, suite)
}
