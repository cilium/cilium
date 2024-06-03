// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-expression-deny.yaml
var clientEgressToEchoExpressionDenyPolicyYAML string

//go:embed manifests/client-egress-to-echo-expression-deny-port-range.yaml
var clientEgressToEchoExpressionDenyPolicyPortRangeYAML string

type clientEgressToEchoExpressionDeny struct{}

func (t clientEgressToEchoExpressionDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoExpressionDenyTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoExpressionDenyTest(ct, true)
	}
}

func clientEgressToEchoExpressionDenyTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-expression-deny"
	policyYAML := clientEgressToEchoExpressionDenyPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-expression-deny-port-range"
		policyYAML = clientEgressToEchoExpressionDenyPolicyPortRangeYAML
	}
	// This policy denies port 8080 from client to echo (using label match expression), but allows traffic from client2
	newTest(testName, ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(policyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})
}
