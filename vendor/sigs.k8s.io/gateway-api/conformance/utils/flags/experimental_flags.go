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

// flags contains command-line flag definitions for the conformance
// profile certification. They're in this package so they can be shared
// among the various suites that are all run by the same Makefile invocation.
package flags

import "flag"

var (
	ImplementationOrganization = flag.String("organization", "", "Implementation's Organization to issue conformance to")
	ImplementationProject      = flag.String("project", "", "Implementation's project to issue conformance to")
	ImplementationURL          = flag.String("url", "", "Implementation's url to issue conformance to")
	ImplementationVersion      = flag.String("version", "", "Implementation's version to issue conformance to")
	ImplementationContact      = flag.String("contact", "", "Comma-separated list of contact information for the maintainers")
	ConformanceProfiles        = flag.String("conformance-profiles", "", "Comma-separated list of the conformance profiles to run")
	ReportOutput               = flag.String("report-output", "", "The file where to write the conformance report")
)
