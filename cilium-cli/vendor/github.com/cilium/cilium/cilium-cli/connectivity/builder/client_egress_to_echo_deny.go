// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-deny.yaml
var clientEgressToEchoDenyPolicyYAML string

type clientEgressToEchoDeny struct{}

func (t clientEgressToEchoDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy denies port 8080 from client to echo
	newTest("client-egress-to-echo-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).         // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML).        // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoDenyPolicyYAML). // Deny client to echo traffic via port 8080
		WithScenarios(
			tests2.ClientToClient(), // Client to client traffic should be allowed
			tests2.PodToPod(),       // Client to echo traffic should be denied
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("kind", "client") &&
				a.Destination().HasLabel("kind", "echo") &&
				a.Destination().Port() == 8080 {
				return check2.ResultPolicyDenyEgressDrop, check2.ResultNone
			}
			return check2.ResultOK, check2.ResultNone
		})
}
