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

// Result is a simple high-level summary describing the conclusion of a test
// run.
type Result string

var (
	// Success indicates that the test run concluded in all required tests
	// passing.
	Success Result = "success"

	// Partial indicates that the test run concluded in some of the required
	// tests passing without any failures, but some were skipped.
	Partial Result = "partial"

	// Failure indicates that the test run concluded in one ore more tests
	// failing to complete successfully.
	Failure Result = "failure"
)
