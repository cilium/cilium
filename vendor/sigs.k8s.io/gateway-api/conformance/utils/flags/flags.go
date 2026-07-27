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
	"net/netip"
	"strings"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	conformanceconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

const (
	// DefaultMode is the operating mode to default to in case no mode is specified.
	DefaultMode                 = "default"
	DefaultGatewayClassName     = "gateway-conformance"
	DefaultCleanupBaseResources = true
	DefaultCleanupTestResources = true
)

// flagSpec holds the apply function for a registered flag override.
type flagSpec struct {
	apply func(opts *suite.ConfigurableOptions)
}

// registry maps flag names to their override functions.
// Override functions are applied when a flag is set to a non-default value.
var registry = map[string]*flagSpec{}

// registerStringFlag registers the override function for a string flag.
func registerStringFlag(flagName, defaultValue, usage string, apply func(*suite.ConfigurableOptions, string)) {
	p := flag.String(flagName, defaultValue, usage)
	registry[flagName] = &flagSpec{
		apply: func(o *suite.ConfigurableOptions) { apply(o, *p) },
	}
}

// registerStringFlag registers the override function for a boolean flag.
func registerBoolFlag(flagName string, defaultValue bool, usage string, apply func(*suite.ConfigurableOptions, bool)) {
	p := flag.Bool(flagName, defaultValue, usage)
	registry[flagName] = &flagSpec{
		apply: func(o *suite.ConfigurableOptions) { apply(o, *p) },
	}
}

var ConformanceOptionsFile = flag.String("conformance-options-file", "", "Path to a YAML file containing the conformance options. Command line flags will override the values in the file.")

func init() {
	registerStringFlag("gateway-class", DefaultGatewayClassName, "Name of GatewayClass to use for tests",
		func(o *suite.ConfigurableOptions, v string) { o.GatewayClassName = v },
	)
	registerStringFlag("mesh-name", "", "Name of Mesh to use for tests",
		func(o *suite.ConfigurableOptions, v string) { o.MeshName = v },
	)
	registerBoolFlag("debug", false, "Whether to print debug logs",
		func(o *suite.ConfigurableOptions, v bool) { o.Debug = v },
	)
	registerBoolFlag("cleanup-base-resources", DefaultCleanupBaseResources, "Whether to cleanup base test resources after the run",
		func(o *suite.ConfigurableOptions, v bool) { o.CleanupBaseResources = v },
	)
	registerBoolFlag("cleanup-test-resources", DefaultCleanupTestResources, "Whether to cleanup test-specific resources after each test",
		func(o *suite.ConfigurableOptions, v bool) { o.CleanupTestResources = v },
	)
	registerStringFlag("supported-features", "", "Supported features included in conformance tests suites",
		func(o *suite.ConfigurableOptions, v string) {
			o.SupportedFeatures = suite.ParseSupportedFeaturesSlice(v)
		},
	)
	registerStringFlag("exempt-features", "", "Exempt Features excluded from conformance tests suites",
		func(o *suite.ConfigurableOptions, v string) { o.ExemptFeatures = suite.ParseSupportedFeaturesSlice(v) },
	)
	registerBoolFlag("all-features", false, "Whether to enable all supported features for conformance tests",
		func(o *suite.ConfigurableOptions, v bool) { o.EnableAllSupportedFeatures = v },
	)
	registerStringFlag("namespace-labels", "", "Comma-separated list of name=value labels to add to test namespaces",
		func(o *suite.ConfigurableOptions, v string) { o.NamespaceLabels = suite.ParseKeyValuePairs(v) },
	)
	registerStringFlag("namespace-annotations", "", "Comma-separated list of name=value annotations to add to test namespaces",
		func(o *suite.ConfigurableOptions, v string) { o.NamespaceAnnotations = suite.ParseKeyValuePairs(v) },
	)
	registerStringFlag("skip-tests", "", "Comma-separated list of tests to skip",
		func(o *suite.ConfigurableOptions, v string) { o.SkipTests = suite.ParseSkipTests(v) },
	)
	registerStringFlag("run-test", "", "Name of a single test to run, instead of the whole suite",
		func(o *suite.ConfigurableOptions, v string) { o.RunTest = v },
	)
	registerStringFlag("mode", DefaultMode, "The operating mode of the implementation.",
		func(o *suite.ConfigurableOptions, v string) { o.Mode = v },
	)
	registerBoolFlag("allow-crds-mismatch", false, "Flag to allow the suite not to fail in case there is a mismatch between CRDs versions and channels.",
		func(o *suite.ConfigurableOptions, v bool) { o.AllowCRDsMismatch = v },
	)
	registerStringFlag("conformance-profiles", "", "Comma-separated list of the conformance profiles to run",
		func(o *suite.ConfigurableOptions, v string) {
			o.ConformanceProfiles = suite.ParseConformanceProfilesSlice(v)
		},
	)
	registerStringFlag("report-output", "", "The file where to write the conformance report",
		func(o *suite.ConfigurableOptions, v string) { o.ReportOutputPath = v },
	)
	registerStringFlag("organization", "", "Implementation's Organization",
		func(o *suite.ConfigurableOptions, v string) { o.Implementation.Organization = v },
	)
	registerStringFlag("project", "", "Implementation's project",
		func(o *suite.ConfigurableOptions, v string) { o.Implementation.Project = v },
	)
	registerStringFlag("url", "", "Implementation's url",
		func(o *suite.ConfigurableOptions, v string) { o.Implementation.URL = v },
	)
	registerStringFlag("version", "", "Implementation's version",
		func(o *suite.ConfigurableOptions, v string) { o.Implementation.Version = v },
	)
	registerStringFlag("contact", "", "Comma-separated list of contact information for the maintainers",
		func(o *suite.ConfigurableOptions, v string) {
			if v == "" {
				o.Implementation.Contact = nil
				return
			}
			o.Implementation.Contact = strings.Split(v, ",")
		},
	)
	registerBoolFlag("skip-provisional-tests", false, "Whether to skip provisional tests",
		func(o *suite.ConfigurableOptions, v bool) { o.SkipProvisionalTests = v },
	)
	registerBoolFlag("fail-fast", false, "Whether to stop the suite execution upon the first test failure",
		func(o *suite.ConfigurableOptions, v bool) { o.FailFast = v },
	)
	registerStringFlag("usable-address", "", "Usable address for GatewayStaticAddresses test",
		func(o *suite.ConfigurableOptions, v string) {
			if v != "" {
				o.UsableNetworkAddresses = []v1.GatewaySpecAddress{parseAddress(v)}
			} else {
				o.UsableNetworkAddresses = nil
			}
		},
	)
	registerStringFlag("unusable-address", "", "Unusable address for GatewayStaticAddresses test",
		func(o *suite.ConfigurableOptions, v string) {
			if v != "" {
				o.UnusableNetworkAddresses = []v1.GatewaySpecAddress{parseAddress(v)}
			} else {
				o.UnusableNetworkAddresses = nil
			}
		},
	)
	registerStringFlag("timeout-config-overrides", "", "Semicolon-separated list of timeout configuration overrides",
		func(o *suite.ConfigurableOptions, v string) {
			conformanceconfig.ParseTimeoutOverrides(&o.TimeoutConfig, v)
		},
	)
}

// Apply flags that were explicitly set by the user.
func ApplyAll(opts *suite.ConfigurableOptions) {
	flag.Visit(func(f *flag.Flag) {
		if spec, ok := registry[f.Name]; ok {
			spec.apply(opts)
		}
	})
}

func parseAddress(v string) v1.GatewaySpecAddress {
	_, err := netip.ParseAddr(v)
	if err == nil {
		return v1.GatewaySpecAddress{
			Type:  new(v1.IPAddressType),
			Value: v,
		}
	}
	return v1.GatewaySpecAddress{
		Type:  new(v1.HostnameAddressType),
		Value: v,
	}
}
