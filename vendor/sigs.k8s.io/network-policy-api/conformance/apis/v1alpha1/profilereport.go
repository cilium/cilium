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

package v1alpha1

// ProfileReport is the generated report for the test results of a specific
// named conformance profile.
type ProfileReport struct {
	// Name indicates the name of the conformance profile
	// (e.g. "ClusterNetworkPolicy")
	Name string `json:"name"`

	// Standard indicates the standard support level which includes the set of tests
	// which are the minimum the implementation must pass to be considered at
	// all conformant.
	Standard Status `json:"standard"`

	// Experimental indicates the experimental support level, which includes additional features
	// that have not yet graduated to Standard.
	Experimental *ExperimentalStatus `json:"experimental,omitempty"`
}

// ExperimentalStatus shows the testing results for the experimental support level.
type ExperimentalStatus struct {
	Status `json:",inline"`

	// SupportedFeatures indicates which experimental features were flagged as
	// supported by the implementation and tests will be attempted for.
	SupportedFeatures []string `json:"supportedFeatures,omitempty"`

	// UnsupportedFeatures indicates which experimental features the implementation
	// does not have support for and therefore will not attempt to test.
	UnsupportedFeatures []string `json:"unsupportedFeatures,omitempty"`
}

// Status includes details on the results of a test.
type Status struct {
	Result `json:"result"`

	// Summary is a human-readable message intended for end-users to understand
	// the overall status at a glance.
	Summary string `json:"summary"`

	// Statistics includes numerical statistics on the result of the test run.
	Statistics `json:"statistics"`

	// SkippedTests indicates which tests were explicitly disabled in the test
	// suite. Skipping tests for Core level support implicitly identifies the
	// results as being partial and the implementation will not be considered
	// conformant at any level.
	SkippedTests []string `json:"skippedTests,omitempty"`

	// FailedTests indicates which tests were failing during the execution of
	// test suite.
	FailedTests []string `json:"failedTests,omitempty"`
}
