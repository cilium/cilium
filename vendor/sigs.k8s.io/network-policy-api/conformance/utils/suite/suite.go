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
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/network-policy-api/conformance"
	"sigs.k8s.io/network-policy-api/conformance/utils/config"
	"sigs.k8s.io/network-policy-api/conformance/utils/kubernetes"
)

const hostNetworkPortsAmount = 8

// ConformanceTestSuite defines the test suite used to run network-policy API
// conformance tests.
type ConformanceTestSuite struct {
	Client                    client.Client
	ClientSet                 k8sclient.Interface
	KubeConfig                rest.Config
	Debug                     bool
	Cleanup                   bool
	BaseManifests             string
	HostNetworkPortRangeStart int
	HostNetworkPortRangeEnd   int
	HostNetworkPorts          []int
	Applier                   kubernetes.Applier
	SupportedFeatures         sets.Set[SupportedFeature]
	TimeoutConfig             config.TimeoutConfig
	SkipTests                 sets.Set[string]
	FS                        embed.FS
}

// Options can be used to initialize a ConformanceTestSuite.
type Options struct {
	Client          client.Client
	ClientSet       k8sclient.Interface
	KubeConfig      rest.Config
	Debug           bool
	BaseManifests   string
	NamespaceLabels map[string]string
	// HostNetworkPortRangeStart and HostNetworkPortRangeEnd allows using a custom port range for host-networked pods.
	// This is useful to avoid port conflicts on different clusters. The range is inclusive of both ends.
	// Currently we use hostNetworkPortsAmount ports, but the amount of used ports can be increased in the future.
	HostNetworkPortRangeStart int
	HostNetworkPortRangeEnd   int

	// CleanupBaseResources indicates whether or not the base test
	// resources such as Namespaces should be cleaned up after the run.
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

	if s.EnableAllSupportedFeatures {
		s.SupportedFeatures = AllFeatures
	} else if s.SupportedFeatures == nil {
		s.SupportedFeatures = StandardFeatures
	} else {
		for feature := range StandardFeatures {
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
		Client:                    s.Client,
		ClientSet:                 s.ClientSet,
		KubeConfig:                s.KubeConfig,
		Debug:                     s.Debug,
		Cleanup:                   s.CleanupBaseResources,
		BaseManifests:             s.BaseManifests,
		HostNetworkPortRangeStart: s.HostNetworkPortRangeStart,
		HostNetworkPortRangeEnd:   s.HostNetworkPortRangeEnd,
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

	return suite
}

// Setup ensures the base resources required for conformance tests are installed
// in the cluster. It also ensures that all relevant resources are ready.
func (suite *ConformanceTestSuite) Setup(t *testing.T) {
	suite.Applier.FS = suite.FS

	if suite.HostNetworkPortRangeStart != 0 && suite.HostNetworkPortRangeEnd == 0 ||
		suite.HostNetworkPortRangeStart == 0 && suite.HostNetworkPortRangeEnd != 0 {
		t.Fatalf("both HostNetworkPortRangeStart and HostNetworkPortRangeEnd must be set or unset together")
	}
	if suite.HostNetworkPortRangeStart == 0 {
		suite.HostNetworkPortRangeStart = 34345
	}
	if suite.HostNetworkPortRangeEnd == 0 {
		suite.HostNetworkPortRangeEnd = suite.HostNetworkPortRangeStart + hostNetworkPortsAmount - 1
	}
	if suite.HostNetworkPortRangeEnd-suite.HostNetworkPortRangeStart+1 < hostNetworkPortsAmount {
		t.Fatalf("the provided host network port range is too small: need at least %d ports", hostNetworkPortsAmount)
	}
	portRange := make([]int, 0, hostNetworkPortsAmount)
	for port := suite.HostNetworkPortRangeStart; port <= suite.HostNetworkPortRangeEnd; port++ {
		portRange = append(portRange, port)
	}
	suite.HostNetworkPorts = portRange
	suite.Applier.HostNetworkPorts = portRange

	if suite.SupportedFeatures.Has(SupportClusterNetworkPolicy) {
		t.Logf("Test Setup: Applying base manifests")
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, suite.BaseManifests, suite.Cleanup)

		t.Logf("Test Setup: Ensuring Namespaces and Pods from base manifests are ready")
		namespaces := []string{
			"network-policy-conformance-gryffindor",
			"network-policy-conformance-slytherin",
			"network-policy-conformance-hufflepuff",
			"network-policy-conformance-ravenclaw",
			"network-policy-conformance-forbidden-forrest",
		}
		statefulSets := []string{
			"harry-potter",
			"draco-malfoy",
			"cedric-diggory",
			"luna-lovegood",
			"centaur",
		}
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, namespaces, statefulSets)
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
