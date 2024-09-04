/*
Copyright 2024 The Kubernetes Authors.

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
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// ConformanceTest is used to define each individual conformance test.
type ConformanceTest struct {
	ShortName   string
	Description string
	Features    []features.FeatureName
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

	var featuresInfo string
	// Test against features if the user hasn't focused on a single test
	if suite.RunTest == "" {
		// Check that all features exercised by the test have been opted into by
		// the suite.
		for i, featureName := range test.Features {
			if !suite.SupportedFeatures.Has(featureName) {
				t.Skipf("Skipping %s: suite does not support %s", test.ShortName, featureName)
			}
			feature := features.GetFeature(featureName)
			featuresInfo = fmt.Sprintf("%s%s-%s", featuresInfo, feature.Name, feature.Channel)
			if i < len(test.Features)-1 {
				featuresInfo += ", "
			}
		}
	}

	// check that the test should not be skipped
	if suite.SkipTests.Has(test.ShortName) || suite.RunTest != "" && suite.RunTest != test.ShortName {
		t.Skipf("Skipping %s: test explicitly skipped", test.ShortName)
	}

	for _, manifestLocation := range test.Manifests {
		tlog.Logf(t, "Applying %s", manifestLocation)
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, manifestLocation, true)
	}

	if featuresInfo != "" {
		tlog.Logf(t, "Running %s, relying on the following features: %s", test.ShortName, featuresInfo)
	}
	test.Test(t, suite)
}

// ParseSupportedFeatures parses flag arguments and converts the string to
// sets.Set[features.FeatureName]
func ParseSupportedFeatures(f string) sets.Set[features.FeatureName] {
	if f == "" {
		return nil
	}
	res := sets.Set[features.FeatureName]{}
	for _, value := range strings.Split(f, ",") {
		res.Insert(features.FeatureName(value))
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
