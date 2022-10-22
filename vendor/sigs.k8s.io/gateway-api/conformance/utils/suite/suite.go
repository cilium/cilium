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

	"golang.org/x/exp/slices"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

// ExemptFeature allows opting out of core conformance tests at an
// individual feature granularity.
type ExemptFeature string

const (
	// This option indicates the implementation is exempting itself from the
	// requirement of a ReferenceGrant to allow cross-namespace references,
	// and has instead implemented alternative safeguards.
	ExemptReferenceGrant ExemptFeature = "ReferenceGrant"
)

// SupportedFeature allows opting in to additional conformance tests at an
// individual feature granularity.
type SupportedFeature string

const (
	// This option indicates support for the ReferenceGrant object.
	SupportReferenceGrant SupportedFeature = "ReferenceGrant"

	// This option indicates support for HTTPRoute query param matching (extended conformance).
	SupportHTTPRouteQueryParamMatching SupportedFeature = "HTTPRouteQueryParamMatching"
)

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
	ExemptFeatures    []ExemptFeature
	SupportedFeatures []SupportedFeature
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
	ValidUniqueListenerPorts []v1alpha2.PortNumber

	// CleanupBaseResources indicates whether or not the base test
	// resources such as Gateways should be cleaned up after the run.
	CleanupBaseResources bool
	ExemptFeatures       []ExemptFeature
	SupportedFeatures    []SupportedFeature
}

// New returns a new ConformanceTestSuite.
func New(s Options) *ConformanceTestSuite {
	roundTripper := s.RoundTripper
	if roundTripper == nil {
		roundTripper = &roundtripper.DefaultRoundTripper{Debug: s.Debug}
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
		ExemptFeatures:    s.ExemptFeatures,
		SupportedFeatures: s.SupportedFeatures,
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
	suite.ControllerName = kubernetes.GWCMustBeAccepted(t, suite.Client, suite.GatewayClassName, 180)

	t.Logf("Test Setup: Applying base manifests")
	suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.BaseManifests, suite.GatewayClassName, suite.Cleanup)

	t.Logf("Test Setup: Applying programmatic resources")
	secret := kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-web-backend", "certificate", []string{"*"})
	suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, []client.Object{secret}, suite.Cleanup)

	t.Logf("Test Setup: Ensuring Gateways and Pods from base manifests are ready")
	namespaces := []string{
		"gateway-conformance-infra",
		"gateway-conformance-app-backend",
		"gateway-conformance-web-backend",
	}
	kubernetes.NamespacesMustBeReady(t, suite.Client, namespaces, 300)
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
	Exemptions  []ExemptFeature
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
		if !slices.Contains(suite.SupportedFeatures, feature) {
			t.Skipf("Skipping %s: suite does not support %s", test.ShortName, feature)
		}
	}

	// Check that no features exercised by the test have been opted out of by
	// the suite.
	for _, feature := range test.Exemptions {
		if slices.Contains(suite.ExemptFeatures, feature) {
			t.Skipf("Skipping %s: suite exempts %s", test.ShortName, feature)
		}
	}

	for _, manifestLocation := range test.Manifests {
		t.Logf("Applying %s", manifestLocation)
		suite.Applier.MustApplyWithCleanup(t, suite.Client, manifestLocation, suite.GatewayClassName, true)
	}

	test.Test(t, suite)
}
