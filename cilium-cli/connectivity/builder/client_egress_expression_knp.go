// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-expression-knp.yaml
var clientEgressToEchoExpressionPolicyKNPYAML string

//go:embed manifests/client-egress-to-echo-expression-knp-port-range.yaml
var clientEgressToEchoExpressionPolicyKNPPortRangeYAML string

type clientEgressExpressionKnp struct{}

func (t clientEgressExpressionKnp) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressExpressionKnpTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressExpressionKnpTest(ct, true)
	}
}

func clientEgressExpressionKnpTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-expression-knp"
	policyYAML := clientEgressToEchoExpressionPolicyKNPYAML
	if portRanges {
		testName = "client-egress-expression-knp-port-range"
		policyYAML = clientEgressToEchoExpressionPolicyKNPPortRangeYAML
	}
	// This policy allows port 8080 from client to echo (using label match expression, so this should succeed
	newTest(testName, ct).
		WithK8SPolicy(policyYAML).
		WithScenarios(tests.PodToPod())
}
