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

// Statistics includes numerical summaries of the number of conformance tests
// that passed, failed or were intentionally skipped.
type Statistics struct {
	// Passed indicates how many tests completed successfully.
	Passed uint32

	// Skipped indicates how many tests were intentionally not run, whether due
	// to lack of feature support or whether they were explicitly disabled in
	// the test suite.
	Skipped uint32

	// Failed indicates how many tests were unsuccessful.
	Failed uint32
}
