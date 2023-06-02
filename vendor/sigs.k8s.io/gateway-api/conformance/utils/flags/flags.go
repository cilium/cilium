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

// flags contains command-line flag definitions for the conformance
// tests. They're in this package so they can be shared among the
// various suites that are all run by the same Makefile invocation.
package flags

import (
	"flag"
)

var (
	GatewayClassName           = flag.String("gateway-class", "gateway-conformance", "Name of GatewayClass to use for tests")
	ShowDebug                  = flag.Bool("debug", false, "Whether to print debug logs")
	CleanupBaseResources       = flag.Bool("cleanup-base-resources", true, "Whether to cleanup base test resources after the run")
	SupportedFeatures          = flag.String("supported-features", "", "Supported features included in conformance tests suites")
	ExemptFeatures             = flag.String("exempt-features", "", "Exempt Features excluded from conformance tests suites")
	EnableAllSupportedFeatures = flag.Bool("all-features", false, "Whether to enable all supported features for conformance tests")
)
