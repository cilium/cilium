/*
Copyright 2023 The Kubernetes Authors.

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
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/gateway-api/conformance"
	confv1a1 "sigs.k8s.io/gateway-api/conformance/apis/v1alpha1"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

// -----------------------------------------------------------------------------
// Conformance Test Suite - Public Types
// -----------------------------------------------------------------------------

// ConformanceTestSuite defines the test suite used to run Gateway API
// conformance tests.
// This is experimental for now and can be used as an alternative to the
// ConformanceTestSuite. Once this won't be experimental any longer,
// the two of them will be merged.
type ExperimentalConformanceTestSuite struct {
	ConformanceTestSuite

	// implementation contains the details of the implementation, such as
	// organization, project, etc.
	implementation confv1a1.Implementation

	// conformanceProfiles is a compiled list of profiles to check
	// conformance against.
	conformanceProfiles sets.Set[ConformanceProfileName]

	// running indicates whether the test suite is currently running
	running bool

	// results stores the pass or fail results of each test that was run by
	// the test suite, organized by the tests unique name.
	results map[string]testResult

	// extendedSupportedFeatures is a compiled list of named features that were
	// marked as supported, and is used for reporting the test results.
	extendedSupportedFeatures map[ConformanceProfileName]sets.Set[SupportedFeature]

	// extendedUnsupportedFeatures is a compiled list of named features that were
	// marked as not supported, and is used for reporting the test results.
	extendedUnsupportedFeatures map[ConformanceProfileName]sets.Set[SupportedFeature]

	// lock is a mutex to help ensure thread safety of the test suite object.
	lock sync.RWMutex
}

// Options can be used to initialize a ConformanceTestSuite.
type ExperimentalConformanceOptions struct {
	Options

	Implementation      confv1a1.Implementation
	ConformanceProfiles sets.Set[ConformanceProfileName]
}

// NewExperimentalConformanceTestSuite is a helper to use for creating a new ExperimentalConformanceTestSuite.
func NewExperimentalConformanceTestSuite(s ExperimentalConformanceOptions) (*ExperimentalConformanceTestSuite, error) {
	config.SetupTimeoutConfig(&s.TimeoutConfig)

	roundTripper := s.RoundTripper
	if roundTripper == nil {
		roundTripper = &roundtripper.DefaultRoundTripper{Debug: s.Debug, TimeoutConfig: s.TimeoutConfig}
	}

	suite := &ExperimentalConformanceTestSuite{
		results:                     make(map[string]testResult),
		extendedUnsupportedFeatures: make(map[ConformanceProfileName]sets.Set[SupportedFeature]),
		extendedSupportedFeatures:   make(map[ConformanceProfileName]sets.Set[SupportedFeature]),
		conformanceProfiles:         s.ConformanceProfiles,
		implementation:              s.Implementation,
	}

	// test suite callers are required to provide a conformance profile OR at
	// minimum a list of features which they support.
	if s.SupportedFeatures == nil && s.ConformanceProfiles.Len() == 0 && !s.EnableAllSupportedFeatures {
		return nil, fmt.Errorf("no conformance profile was selected for test run, and no supported features were provided so no tests could be selected")
	}

	// test suite callers can potentially just run all tests by saying they
	// cover all features, if they don't they'll need to have provided a
	// conformance profile or at least some specific features they support.
	if s.EnableAllSupportedFeatures {
		s.SupportedFeatures = AllFeatures
	} else {
		if s.SupportedFeatures == nil {
			s.SupportedFeatures = sets.New[SupportedFeature]()
		}

		for _, conformanceProfileName := range s.ConformanceProfiles.UnsortedList() {
			conformanceProfile, err := getConformanceProfileForName(conformanceProfileName)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve conformance profile: %w", err)
			}
			// the use of a conformance profile implicitly enables any features of
			// that profile which are supported at a Core level of support.
			for _, f := range conformanceProfile.CoreFeatures.UnsortedList() {
				if !s.SupportedFeatures.Has(f) {
					s.SupportedFeatures.Insert(f)
				}
			}
			for _, f := range conformanceProfile.ExtendedFeatures.UnsortedList() {
				if s.SupportedFeatures.Has(f) {
					if suite.extendedSupportedFeatures[conformanceProfileName] == nil {
						suite.extendedSupportedFeatures[conformanceProfileName] = sets.New[SupportedFeature]()
					}
					suite.extendedSupportedFeatures[conformanceProfileName].Insert(f)
				} else {
					if suite.extendedUnsupportedFeatures[conformanceProfileName] == nil {
						suite.extendedUnsupportedFeatures[conformanceProfileName] = sets.New[SupportedFeature]()
					}
					suite.extendedUnsupportedFeatures[conformanceProfileName].Insert(f)
				}
			}
		}
	}

	if s.FS == nil {
		s.FS = &conformance.Manifests
	}

	suite.ConformanceTestSuite = ConformanceTestSuite{
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

	return suite, nil
}

// -----------------------------------------------------------------------------
// Conformance Test Suite - Public Methods
// -----------------------------------------------------------------------------

// Setup ensures the base resources required for conformance tests are installed
// in the cluster. It also ensures that all relevant resources are ready.
func (suite *ExperimentalConformanceTestSuite) Setup(t *testing.T) {
	suite.ConformanceTestSuite.Setup(t)
}

// Run runs the provided set of conformance tests.
func (suite *ExperimentalConformanceTestSuite) Run(t *testing.T, tests []ConformanceTest) error {
	// verify that the test suite isn't already running, don't start a new run
	// until the previous run finishes
	suite.lock.Lock()
	if suite.running {
		suite.lock.Unlock()
		return fmt.Errorf("can't run the test suite multiple times in parallel: the test suite is already running")
	}

	// if the test suite is not currently running, reset reporting and start a
	// new test run.
	suite.running = true
	suite.results = nil
	suite.lock.Unlock()

	// run all tests and collect the test results for conformance reporting
	results := make(map[string]testResult)
	for _, test := range tests {
		succeeded := t.Run(test.ShortName, func(t *testing.T) {
			test.Run(t, &suite.ConformanceTestSuite)
		})
		res := testSucceeded
		if suite.SkipTests.Has(test.ShortName) {
			res = testSkipped
		}
		if !suite.SupportedFeatures.HasAll(test.Features...) {
			res = testNotSupported
		}

		if !succeeded {
			res = testFailed
		}

		results[test.ShortName] = testResult{
			test:   test,
			result: res,
		}
	}

	// now that the tests have completed, mark the test suite as not running
	// and report the test results.
	suite.lock.Lock()
	suite.running = false
	suite.results = results
	suite.lock.Unlock()

	return nil
}

// Report emits a ConformanceReport for the previously completed test run.
// If no run completed prior to running the report, and error is emitted.
func (suite *ExperimentalConformanceTestSuite) Report() (*confv1a1.ConformanceReport, error) {
	suite.lock.RLock()
	if suite.running {
		suite.lock.RUnlock()
		return nil, fmt.Errorf("can't generate report: the test suite is currently running")
	}
	defer suite.lock.RUnlock()

	profileReports := newReports()
	for _, testResult := range suite.results {
		conformanceProfiles := getConformanceProfilesForTest(testResult.test, suite.conformanceProfiles)
		for _, profile := range conformanceProfiles.UnsortedList() {
			profileReports.addTestResults(*profile, testResult)
		}
	}

	profileReports.compileResults(suite.extendedSupportedFeatures, suite.extendedUnsupportedFeatures)

	return &confv1a1.ConformanceReport{
		TypeMeta: v1.TypeMeta{
			APIVersion: "gateway.networking.k8s.io/v1alpha1",
			Kind:       "ConformanceReport",
		},
		Date:              time.Now().Format(time.RFC3339),
		Implementation:    suite.implementation,
		GatewayAPIVersion: "TODO",
		ProfileReports:    profileReports.list(),
	}, nil
}

// ParseImplementation parses implementation-specific flag arguments and
// creates a *confv1a1.Implementation.
func ParseImplementation(org, project, url, version, contact string) (*confv1a1.Implementation, error) {
	if org == "" {
		return nil, errors.New("implementation's organization can not be empty")
	}
	if project == "" {
		return nil, errors.New("implementation's project can not be empty")
	}
	if url == "" {
		return nil, errors.New("implementation's url can not be empty")
	}
	if version == "" {
		return nil, errors.New("implementation's version can not be empty")
	}
	contacts := strings.Split(contact, ",")
	if len(contacts) == 0 {
		return nil, errors.New("implementation's contact can not be empty")
	}

	// TODO: add data validation https://github.com/kubernetes-sigs/gateway-api/issues/2178

	return &confv1a1.Implementation{
		Organization: org,
		Project:      project,
		URL:          url,
		Version:      version,
		Contact:      contacts,
	}, nil
}

// ParseConformanceProfiles parses flag arguments and converts the string to
// sets.Set[ConformanceProfileName].
func ParseConformanceProfiles(p string) sets.Set[ConformanceProfileName] {
	res := sets.Set[ConformanceProfileName]{}
	if p == "" {
		return res
	}

	for _, value := range strings.Split(p, ",") {
		res.Insert(ConformanceProfileName(value))
	}
	return res
}
