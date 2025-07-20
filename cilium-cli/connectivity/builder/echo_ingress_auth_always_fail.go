// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-mutual-authentication-fail.yaml
var echoIngressAuthFailPolicyYAML string

//go:embed manifests/echo-ingress-mutual-authentication-fail-port-range.yaml
var echoIngressAuthFailPolicyPortRangeYAML string

type echoIngressAuthAlwaysFail struct{}

func (t echoIngressAuthAlwaysFail) build(ct *check.ConnectivityTest, _ map[string]string) {
	echoIngressAuthAlwaysFailTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		echoIngressAuthAlwaysFailTest(ct, true)
	}
}

func echoIngressAuthAlwaysFailTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "echo-ingress-auth-always-fail"
	policyYAML := echoIngressAuthFailPolicyYAML
	if portRanges {
		testName = "echo-ingress-auth-always-fail-port-range"
		policyYAML = echoIngressAuthFailPolicyPortRangeYAML
	}
	// Test mutual auth with always-fail
	newTest(testName, ct).
		WithCiliumPolicy(policyYAML).
		// this test is only useful when auth is supported in the Cilium version and it is enabled
		// currently this is tested spiffe as that is the only functional auth method
		WithFeatureRequirements(features.RequireEnabled(features.AuthSpiffe)).
		WithScenarios(tests.PodToPod()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultDropAuthRequired
		})
}
