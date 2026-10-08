// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/echo-ingress-from-other-client-deny.yaml
var echoIngressFromOtherClientDenyPolicyYAML string

type echoIngressFromOtherClientDeny struct{}

func (t echoIngressFromOtherClientDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Tests with deny policy
	newTest("echo-ingress-from-other-client-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).                 // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).                // Allow all ingress traffic
		WithCiliumPolicy(echoIngressFromOtherClientDenyPolicyYAML). // Deny other client contact echo
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
			tests.ClientToClient(), // Client to client should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") && a.Destination().HasLabel("kind", "echo") {
				return check.ResultDrop, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})
}
