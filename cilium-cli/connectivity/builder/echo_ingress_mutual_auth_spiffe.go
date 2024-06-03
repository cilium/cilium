// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-mutual-authentication.yaml
var echoIngressMutualAuthPolicyYAML string

//go:embed manifests/echo-ingress-mutual-authentication-port-range.yaml
var echoIngressMutualAuthPolicyPortRangeYAML string

type echoIngressMutualAuthSpiffe struct{}

func (t echoIngressMutualAuthSpiffe) build(ct *check.ConnectivityTest, _ map[string]string) {
	echoIngressMutualAuthSpiffeTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		echoIngressMutualAuthSpiffeTest(ct, true)
	}
}

func echoIngressMutualAuthSpiffeTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "echo-ingress-mutual-auth-spiffe"
	policyYAML := echoIngressMutualAuthPolicyYAML
	if portRanges {
		testName = "echo-ingress-mutual-auth-spiffe-port-range"
		policyYAML = echoIngressMutualAuthPolicyPortRangeYAML
	}
	// Test mutual auth with SPIFFE
	newTest(testName, ct).
		WithCiliumPolicy(policyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.AuthSpiffe)).
		WithScenarios(tests.PodToPod())
}
