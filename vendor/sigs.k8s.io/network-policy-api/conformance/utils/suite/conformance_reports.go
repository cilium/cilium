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
	"k8s.io/apimachinery/pkg/util/sets"

	confv1a1 "sigs.k8s.io/network-policy-api/conformance/apis/v1alpha1"
)

// -----------------------------------------------------------------------------
// ConformanceReport - Private Types
// -----------------------------------------------------------------------------

type testResult struct {
	test   ConformanceTest
	result resultType
}

type resultType string

var (
	testSucceeded    resultType = "SUCCEEDED"
	testFailed       resultType = "FAILED"
	testSkipped      resultType = "SKIPPED"
	testNotSupported resultType = "NOT_SUPPORTED"
)

type profileReportsMap map[ConformanceProfileName]confv1a1.ProfileReport

func newReports() profileReportsMap {
	return make(profileReportsMap)
}

func (p profileReportsMap) addTestResults(conformanceProfile ConformanceProfile, result testResult) {
	// initialize the profile report if not already initialized
	if _, ok := p[conformanceProfile.Name]; !ok {
		p[conformanceProfile.Name] = confv1a1.ProfileReport{
			Name: string(conformanceProfile.Name),
		}
	}

	testIsExperimental := isTestExperimental(conformanceProfile, result.test)
	report := p[conformanceProfile.Name]

	switch result.result {
	case testSucceeded:
		if testIsExperimental {
			if report.Experimental == nil {
				report.Experimental = &confv1a1.ExperimentalStatus{}
			}
			report.Experimental.Statistics.Passed++

		} else {
			report.Standard.Statistics.Passed++
		}
	case testFailed:
		if testIsExperimental {
			if report.Experimental == nil {
				report.Experimental = &confv1a1.ExperimentalStatus{}
			}
			if report.Experimental.FailedTests == nil {
				report.Experimental.FailedTests = []string{}
			}
			report.Experimental.FailedTests = append(report.Experimental.FailedTests, result.test.ShortName)
			report.Experimental.Statistics.Failed++
		} else {
			report.Standard.Statistics.Failed++
			if report.Standard.FailedTests == nil {
				report.Standard.FailedTests = []string{}
			}
			report.Standard.FailedTests = append(report.Standard.FailedTests, result.test.ShortName)
		}
	case testSkipped:
		if testIsExperimental {
			if report.Experimental == nil {
				report.Experimental = &confv1a1.ExperimentalStatus{}
			}
			report.Experimental.Statistics.Skipped++
			if report.Experimental.SkippedTests == nil {
				report.Experimental.SkippedTests = []string{}
			}
			report.Experimental.SkippedTests = append(report.Experimental.SkippedTests, result.test.ShortName)
		} else {
			report.Standard.Statistics.Skipped++
			if report.Standard.SkippedTests == nil {
				report.Standard.SkippedTests = []string{}
			}
			report.Standard.SkippedTests = append(report.Standard.SkippedTests, result.test.ShortName)
		}
	}
	p[conformanceProfile.Name] = report
}

func (p profileReportsMap) list() (profileReports []confv1a1.ProfileReport) {
	for _, profileReport := range p {
		profileReports = append(profileReports, profileReport)
	}
	return
}

func (p profileReportsMap) compileResults(supportedFeaturesMap map[ConformanceProfileName]sets.Set[SupportedFeature], unsupportedFeaturesMap map[ConformanceProfileName]sets.Set[SupportedFeature]) {
	for key, report := range p {
		// report the overall result for Standard features
		if report.Standard.Failed > 0 {
			report.Standard.Result = confv1a1.Failure
		} else if report.Standard.Skipped > 0 {
			report.Standard.Result = confv1a1.Partial
		} else {
			report.Standard.Result = confv1a1.Success
		}

		if report.Experimental != nil {
			// report the overall result for Experimental features
			if report.Experimental.Failed > 0 {
				report.Experimental.Result = confv1a1.Failure
			} else if report.Experimental.Skipped > 0 {
				report.Experimental.Result = confv1a1.Partial
			} else {
				report.Experimental.Result = confv1a1.Success
			}
		}
		p[key] = report

		supportedFeatures := supportedFeaturesMap[ConformanceProfileName(report.Name)]
		if report.Experimental != nil {
			if supportedFeatures != nil {
				if report.Experimental.SupportedFeatures == nil {
					report.Experimental.SupportedFeatures = make([]string, 0)
				}
				for _, f := range supportedFeatures.UnsortedList() {
					report.Experimental.SupportedFeatures = append(report.Experimental.SupportedFeatures, string(f))
				}
			}
		}

		unsupportedFeatures := unsupportedFeaturesMap[ConformanceProfileName(report.Name)]
		if report.Experimental != nil {
			if unsupportedFeatures != nil {
				if report.Experimental.UnsupportedFeatures == nil {
					report.Experimental.UnsupportedFeatures = make([]string, 0)
				}
				for _, f := range unsupportedFeatures.UnsortedList() {
					report.Experimental.UnsupportedFeatures = append(report.Experimental.UnsupportedFeatures, string(f))
				}
			}
		}
	}
}

// -----------------------------------------------------------------------------
// ConformanceReport - Private Helper Functions
// -----------------------------------------------------------------------------

// isTestExperimental determines if a provided test is considered to be supported
// at an experimental level of support given the provided conformance profile.
//
// TODO: right now the tests themselves don't indicate the conformance
// support level associated with them. The only way we have right now
// in this prototype to know whether a test belongs to any particular
// conformance level is to compare the features needed for the test to
// the conformance profiles known list of Standard vs Experimental features.
// We should fix this to indicate the conformance support level of each
// test, but for now this hack works.
func isTestExperimental(profile ConformanceProfile, test ConformanceTest) bool {
	for _, supportedFeature := range test.Features {
		// if ANY of the features needed for the test are experimental features,
		// then we consider the entire test experimental level support.
		if profile.ExperimentalFeatures.Has(supportedFeature) {
			return true
		}
	}
	return false
}
