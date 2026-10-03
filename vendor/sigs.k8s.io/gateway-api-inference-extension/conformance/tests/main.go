/*
Copyright 2025 The Kubernetes Authors.

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

// Package tests is the root package for all Gateway API Inference Extension
// conformance test implementations.
package tests

import (
	// Importing the suite package to access the ConformanceTest struct definition.
	// For initial version directly importing from the core gateway-api repo.
	// This may be adjusted in the future if we have need to create a copy of
	// the suite utilities.
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	// Do NOT add blank imports for specific test packages here.
	// They should be added to the main conformance package instead
	// to avoid import cycles.
)

// ConformanceTests holds all the conformance tests definitions for the
// Gateway API Inference Extension suite. Tests are registered from other packages
// using init() functions like the one in the basic package.
var ConformanceTests []suite.ConformanceTest
