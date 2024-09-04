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
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/util/sets"

	confv1 "sigs.k8s.io/gateway-api/conformance/apis/v1"
	"sigs.k8s.io/gateway-api/pkg/features"
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

type profileReportsMap map[ConformanceProfileName]confv1.ProfileReport

func newReports() profileReportsMap {
	return make(profileReportsMap)
}

func (p profileReportsMap) addTestResults(conformanceProfile ConformanceProfile, result testResult) {
	// initialize the profile report if not already initialized
	if _, ok := p[conformanceProfile.Name]; !ok {
		p[conformanceProfile.Name] = confv1.ProfileReport{
			Name: string(conformanceProfile.Name),
		}
	}

	testIsExtended := isTestExtended(conformanceProfile, result.test)
	report := p[conformanceProfile.Name]

	switch result.result {
	case testSucceeded:
		if testIsExtended {
			if report.Extended == nil {
				report.Extended = &confv1.ExtendedStatus{}
			}
			report.Extended.Statistics.Passed++
		} else {
			report.Core.Statistics.Passed++
		}
	case testFailed:
		if testIsExtended {
			if report.Extended == nil {
				report.Extended = &confv1.ExtendedStatus{}
			}
			report.Extended.FailedTests = append(report.Extended.FailedTests, result.test.ShortName)
			report.Extended.Statistics.Failed++
		} else {
			report.Core.Statistics.Failed++
			if report.Core.FailedTests == nil {
				report.Core.FailedTests = []string{}
			}
			report.Core.FailedTests = append(report.Core.FailedTests, result.test.ShortName)
		}
	case testSkipped:
		if testIsExtended {
			if report.Extended == nil {
				report.Extended = &confv1.ExtendedStatus{}
			}
			report.Extended.Statistics.Skipped++
			report.Extended.SkippedTests = append(report.Extended.SkippedTests, result.test.ShortName)
		} else {
			report.Core.Statistics.Skipped++
			report.Core.SkippedTests = append(report.Core.SkippedTests, result.test.ShortName)
		}
	}
	p[conformanceProfile.Name] = report
}

func (p profileReportsMap) list() (profileReports []confv1.ProfileReport) {
	for _, profileReport := range p {
		profileReports = append(profileReports, profileReport)
	}
	return
}

func (p profileReportsMap) compileResults(supportedFeaturesMap map[ConformanceProfileName]sets.Set[features.FeatureName], unsupportedFeaturesMap map[ConformanceProfileName]sets.Set[features.FeatureName]) {
	for key, report := range p {
		// report the overall result for core features
		switch {
		case report.Core.Failed > 0:
			report.Core.Result = confv1.Failure
		case report.Core.Skipped > 0:
			report.Core.Result = confv1.Partial
		default:
			report.Core.Result = confv1.Success
		}

		if report.Extended != nil {
			// report the overall result for extended features
			switch {
			case report.Extended.Failed > 0:
				report.Extended.Result = confv1.Failure
			case report.Extended.Skipped > 0:
				report.Extended.Result = confv1.Partial
			default:
				report.Extended.Result = confv1.Success
			}
		}
		report.Summary = buildSummary(report)
		p[key] = report

		supportedFeatures := supportedFeaturesMap[ConformanceProfileName(report.Name)]
		if report.Extended != nil {
			if supportedFeatures != nil {
				supportedFeatures := supportedFeatures.UnsortedList()
				sort.Slice(supportedFeatures, func(i, j int) bool {
					return supportedFeatures[i] < supportedFeatures[j]
				})
				for _, f := range supportedFeatures {
					report.Extended.SupportedFeatures = append(report.Extended.SupportedFeatures, string(f))
				}
			}
		}

		unsupportedFeatures := unsupportedFeaturesMap[ConformanceProfileName(report.Name)]
		if report.Extended != nil {
			if unsupportedFeatures != nil {
				unsupportedFeatures := unsupportedFeatures.UnsortedList()
				sort.Slice(unsupportedFeatures, func(i, j int) bool {
					return unsupportedFeatures[i] < unsupportedFeatures[j]
				})
				for _, f := range unsupportedFeatures {
					report.Extended.UnsupportedFeatures = append(report.Extended.UnsupportedFeatures, string(f))
				}
			}
		}
	}
}

// -----------------------------------------------------------------------------
// ConformanceReport - Private Helper Functions
// -----------------------------------------------------------------------------

// isTestExtended determines if a provided test is considered to be supported
// at an extended level of support given the provided conformance profile.
//
// TODO: right now the tests themselves don't indicate the conformance
// support level associated with them. The only way we have right now
// in this prototype to know whether a test belongs to any particular
// conformance level is to compare the features needed for the test to
// the conformance profiles known list of core vs extended features.
// Later if we move out of Prototyping/Provisional it would probably
// be best to indicate the conformance support level of each test, but
// for now this hack works.
func isTestExtended(profile ConformanceProfile, test ConformanceTest) bool {
	for _, supportedFeature := range test.Features {
		// if ANY of the features needed for the test are extended features,
		// then we consider the entire test extended level support.
		if !profile.CoreFeatures.Has(supportedFeature) {
			return true
		}
	}
	return false
}

// buildSummary creates a human-readable message about each profile's test outcomes.
func buildSummary(report confv1.ProfileReport) (reportSummary string) {
	reportSummary = fmt.Sprintf("Core tests %s", buildReportSummary(report.Core))
	if report.Extended != nil {
		reportSummary = fmt.Sprintf("%s. Extended tests %s", reportSummary, buildReportSummary(report.Extended.Status))
	}
	return fmt.Sprintf("%s.", reportSummary)
}

func buildReportSummary(status confv1.Status) string {
	var message string
	switch status.Result {
	case confv1.Success:
		message = "succeeded"
	case confv1.Partial:
		message = fmt.Sprintf("partially succeeded with %d test skips", status.Statistics.Skipped)
	case confv1.Failure:
		message = fmt.Sprintf("failed with %d test failures", status.Statistics.Failed)
	}
	return message
}
