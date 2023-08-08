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
	"embed"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

// ConformanceTestSuite defines the test suite used to run Gateway API
// conformance tests.
type ConformanceTestSuite struct {
	Client            client.Client
	Clientset         *clientset.Clientset
	RESTClient        *rest.RESTClient
	RestConfig        *rest.Config
	RoundTripper      roundtripper.RoundTripper
	GatewayClassName  string
	ControllerName    string
	Debug             bool
	Cleanup           bool
	BaseManifests     string
	MeshManifests     string
	Applier           kubernetes.Applier
	SupportedFeatures sets.Set[SupportedFeature]
	TimeoutConfig     config.TimeoutConfig
	SkipTests         sets.Set[string]
	FS                embed.FS
}

// Options can be used to initialize a ConformanceTestSuite.
type Options struct {
	Client           client.Client
	Clientset        *clientset.Clientset
	RESTClient       *rest.RESTClient
	RestConfig       *rest.Config
	GatewayClassName string
	Debug            bool
	RoundTripper     roundtripper.RoundTripper
	BaseManifests    string
	MeshManifests    string
	NamespaceLabels  map[string]string

	// CleanupBaseResources indicates whether or not the base test
	// resources such as Gateways should be cleaned up after the run.
	CleanupBaseResources       bool
	SupportedFeatures          sets.Set[SupportedFeature]
	ExemptFeatures             sets.Set[SupportedFeature]
	EnableAllSupportedFeatures bool
	TimeoutConfig              config.TimeoutConfig
	// SkipTests contains all the tests not to be run and can be used to opt out
	// of specific tests
	SkipTests []string

	FS *embed.FS
}

// New returns a new ConformanceTestSuite.
func New(s Options) *ConformanceTestSuite {
	config.SetupTimeoutConfig(&s.TimeoutConfig)

	roundTripper := s.RoundTripper
	if roundTripper == nil {
		roundTripper = &roundtripper.DefaultRoundTripper{Debug: s.Debug, TimeoutConfig: s.TimeoutConfig}
	}

	if s.EnableAllSupportedFeatures == true {
		s.SupportedFeatures = AllFeatures
	} else if s.SupportedFeatures == nil {
		s.SupportedFeatures = StandardCoreFeatures
	} else {
		for feature := range StandardCoreFeatures {
			s.SupportedFeatures.Insert(feature)
		}
	}

	for feature := range s.ExemptFeatures {
		s.SupportedFeatures.Delete(feature)
	}

	if s.FS == nil {
		s.FS = &conformance.Manifests
	}

	suite := &ConformanceTestSuite{
		Client:           s.Client,
		Clientset:        s.Clientset,
		RESTClient:       s.RESTClient,
		RestConfig:       s.RestConfig,
		RoundTripper:     roundTripper,
		GatewayClassName: s.GatewayClassName,
		Debug:            s.Debug,
		Cleanup:          s.CleanupBaseResources,
		BaseManifests:    s.BaseManifests,
		MeshManifests:    s.MeshManifests,
		Applier: kubernetes.Applier{
			NamespaceLabels: s.NamespaceLabels,
		},
		SupportedFeatures: s.SupportedFeatures,
		TimeoutConfig:     s.TimeoutConfig,
		SkipTests:         sets.New(s.SkipTests...),
		FS:                *s.FS,
	}

	// apply defaults
	if suite.BaseManifests == "" {
		suite.BaseManifests = "base/manifests.yaml"
	}
	if suite.MeshManifests == "" {
		suite.MeshManifests = "mesh/manifests.yaml"
	}

	return suite
}

// Setup ensures the base resources required for conformance tests are installed
// in the cluster. It also ensures that all relevant resources are ready.
func (suite *ConformanceTestSuite) Setup(t *testing.T) {
	t.Logf("Test Setup: Ensuring GatewayClass has been accepted")
	suite.ControllerName = kubernetes.GWCMustHaveAcceptedConditionTrue(t, suite.Client, suite.TimeoutConfig, suite.GatewayClassName)

	suite.Applier.GatewayClass = suite.GatewayClassName
	suite.Applier.ControllerName = suite.ControllerName
	suite.Applier.FS = suite.FS

	if suite.SupportedFeatures.Has(SupportGateway) {
		t.Logf("Test Setup: Applying base manifests")
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, suite.BaseManifests, suite.Cleanup)

		t.Logf("Test Setup: Applying programmatic resources")
		secret := kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-web-backend", "certificate", []string{"*"})
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)
		secret = kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-infra", "tls-validity-checks-certificate", []string{"*", "*.org"})
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)
		secret = kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-infra", "tls-passthrough-checks-certificate", []string{"abc.example.com"})
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)

		t.Logf("Test Setup: Ensuring Gateways and Pods from base manifests are ready")
		namespaces := []string{
			"gateway-conformance-infra",
			"gateway-conformance-app-backend",
			"gateway-conformance-web-backend",
		}
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, namespaces)
	}
	if suite.SupportedFeatures.Has(SupportMesh) {
		t.Logf("Test Setup: Applying base manifests")
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, suite.MeshManifests, suite.Cleanup)
		t.Logf("Test Setup: Ensuring Gateways and Pods from base manifests are ready")
		namespaces := []string{
			"gateway-conformance-mesh",
			"gateway-conformance-app-backend",
			"gateway-conformance-web-backend",
		}
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, namespaces)
	}
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
		if !suite.SupportedFeatures.Has(feature) {
			t.Skipf("Skipping %s: suite does not support %s", test.ShortName, feature)
		}
	}

	// check that the test should not be skipped
	if suite.SkipTests.Has(test.ShortName) {
		t.Logf("Skipping %s", test.ShortName)
		return
	}

	for _, manifestLocation := range test.Manifests {
		t.Logf("Applying %s", manifestLocation)
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, manifestLocation, true)
	}

	test.Test(t, suite)
}
