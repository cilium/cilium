// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-expression-deny.yaml
var clientEgressToEchoExpressionDenyPolicyYAML string

type clientEgressToEchoExpressionDeny struct{}

func (t clientEgressToEchoExpressionDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy denies port 8080 from client to echo (using label match expression), but allows traffic from client2
	newTest("client-egress-to-echo-expression-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoExpressionDenyPolicyYAML).
		WithScenarios(
			tests2.PodToPod(tests2.WithSourceLabelsOption(clientLabel)),  // Client to echo should be denied
			tests2.PodToPod(tests2.WithSourceLabelsOption(client2Label)), // Client2 to echo should be allowed
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check2.ResultPolicyDenyEgressDrop, check2.ResultNone
			}
			return check2.ResultOK, check2.ResultOK
		})
}
