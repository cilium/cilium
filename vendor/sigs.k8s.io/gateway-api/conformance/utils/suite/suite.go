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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

// ConformanceTestSuite defines the test suite used to run Gateway API
// conformance tests.
type ConformanceTestSuite struct {
	Client                   client.Client
	Clientset                clientset.Interface
	RESTClient               *rest.RESTClient
	RestConfig               *rest.Config
	RoundTripper             roundtripper.RoundTripper
	GatewayClassName         string
	ControllerName           string
	Debug                    bool
	Cleanup                  bool
	BaseManifests            string
	MeshManifests            string
	Applier                  kubernetes.Applier
	SupportedFeatures        sets.Set[SupportedFeature]
	TimeoutConfig            config.TimeoutConfig
	SkipTests                sets.Set[string]
	RunTest                  string
	FS                       embed.FS
	UsableNetworkAddresses   []v1beta1.GatewayAddress
	UnusableNetworkAddresses []v1beta1.GatewayAddress
}

// Options can be used to initialize a ConformanceTestSuite.
type Options struct {
	Client               client.Client
	Clientset            clientset.Interface
	RestConfig           *rest.Config
	GatewayClassName     string
	Debug                bool
	RoundTripper         roundtripper.RoundTripper
	BaseManifests        string
	MeshManifests        string
	NamespaceLabels      map[string]string
	NamespaceAnnotations map[string]string

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
	// RunTest is a single test to run, mostly for development/debugging convenience.
	RunTest string

	FS *embed.FS

	// UsableNetworkAddresses is an optional pool of usable addresses for
	// Gateways for tests which need to test manual address assignments.
	UsableNetworkAddresses []v1beta1.GatewayAddress

	// UnusableNetworkAddresses is an optional pool of unusable addresses for
	// Gateways for tests which need to test failures with manual Gateway
	// address assignment.
	UnusableNetworkAddresses []v1beta1.GatewayAddress
}

// New returns a new ConformanceTestSuite.
func New(s Options) *ConformanceTestSuite {
	config.SetupTimeoutConfig(&s.TimeoutConfig)

	roundTripper := s.RoundTripper
	if roundTripper == nil {
		roundTripper = &roundtripper.DefaultRoundTripper{Debug: s.Debug, TimeoutConfig: s.TimeoutConfig}
	}

	switch {
	case s.EnableAllSupportedFeatures:
		s.SupportedFeatures = AllFeatures
	case s.SupportedFeatures == nil:
		s.SupportedFeatures = GatewayCoreFeatures
	default:
		for feature := range GatewayCoreFeatures {
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
		RestConfig:       s.RestConfig,
		RoundTripper:     roundTripper,
		GatewayClassName: s.GatewayClassName,
		Debug:            s.Debug,
		Cleanup:          s.CleanupBaseResources,
		BaseManifests:    s.BaseManifests,
		MeshManifests:    s.MeshManifests,
		Applier: kubernetes.Applier{
			NamespaceLabels:      s.NamespaceLabels,
			NamespaceAnnotations: s.NamespaceAnnotations,
		},
		SupportedFeatures:        s.SupportedFeatures,
		TimeoutConfig:            s.TimeoutConfig,
		SkipTests:                sets.New(s.SkipTests...),
		RunTest:                  s.RunTest,
		FS:                       *s.FS,
		UsableNetworkAddresses:   s.UsableNetworkAddresses,
		UnusableNetworkAddresses: s.UnusableNetworkAddresses,
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
	suite.Applier.FS = suite.FS
	suite.Applier.UsableNetworkAddresses = suite.UsableNetworkAddresses
	suite.Applier.UnusableNetworkAddresses = suite.UnusableNetworkAddresses

	if suite.SupportedFeatures.Has(SupportGateway) {
		t.Logf("Test Setup: Ensuring GatewayClass has been accepted")
		suite.ControllerName = kubernetes.GWCMustHaveAcceptedConditionTrue(t, suite.Client, suite.TimeoutConfig, suite.GatewayClassName)

		suite.Applier.GatewayClass = suite.GatewayClassName
		suite.Applier.ControllerName = suite.ControllerName

		t.Logf("Test Setup: Applying base manifests")
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, suite.BaseManifests, suite.Cleanup)

		t.Logf("Test Setup: Applying programmatic resources")
		secret := kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-web-backend", "certificate", []string{"*"})
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)
		secret = kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-infra", "tls-validity-checks-certificate", []string{"*", "*.org"})
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)
		secret = kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-infra", "tls-passthrough-checks-certificate", []string{"abc.example.com"})
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{secret}, suite.Cleanup)
		secret = kubernetes.MustCreateSelfSignedCertSecret(t, "gateway-conformance-app-backend", "tls-passthrough-checks-certificate", []string{"abc.example.com"})
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
		t.Logf("Test Setup: Ensuring Gateways and Pods from mesh manifests are ready")
		namespaces := []string{
			"gateway-conformance-mesh",
			"gateway-conformance-mesh-consumer",
			"gateway-conformance-app-backend",
			"gateway-conformance-web-backend",
		}
		kubernetes.MeshNamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, namespaces)
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
	if suite.SkipTests.Has(test.ShortName) || suite.RunTest != "" && suite.RunTest != test.ShortName {
		t.Skipf("Skipping %s: test explicitly skipped", test.ShortName)
	}

	for _, manifestLocation := range test.Manifests {
		t.Logf("Applying %s", manifestLocation)
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, manifestLocation, true)
	}

	test.Test(t, suite)
}

// ParseSupportedFeatures parses flag arguments and converts the string to
// sets.Set[suite.SupportedFeature]
func ParseSupportedFeatures(f string) sets.Set[SupportedFeature] {
	if f == "" {
		return nil
	}
	res := sets.Set[SupportedFeature]{}
	for _, value := range strings.Split(f, ",") {
		res.Insert(SupportedFeature(value))
	}
	return res
}

// ParseKeyValuePairs parses flag arguments and converts the string to
// map[string]string containing label key/value pairs.
func ParseKeyValuePairs(f string) map[string]string {
	if f == "" {
		return nil
	}
	res := map[string]string{}
	for _, kv := range strings.Split(f, ",") {
		parts := strings.Split(kv, "=")
		if len(parts) == 2 {
			res[parts[0]] = parts[1]
		}
	}
	return res
}

// ParseSkipTests parses flag arguments and converts the string to
// []string containing the tests to be skipped.
func ParseSkipTests(t string) []string {
	if t == "" {
		return nil
	}
	return strings.Split(t, ",")
}
