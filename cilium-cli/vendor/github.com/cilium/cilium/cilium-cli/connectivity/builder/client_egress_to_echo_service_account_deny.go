// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-service-account-deny.yaml
var clientEgressToEchoServiceAccountDenyPolicyYAML string

type clientEgressToEchoServiceAccountDeny struct{}

func (t clientEgressToEchoServiceAccountDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy denies port 8080 from client to endpoint with service account, but not from client2
	newTest("client-egress-to-echo-service-account-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoServiceAccountDenyPolicyYAML).
		WithScenarios(
			tests2.PodToPod(tests2.WithSourceLabelsOption(map[string]string{"name": "client"})),
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check2.ResultPolicyDenyEgressDrop, check2.ResultNone
			}
			return check2.ResultOK, check2.ResultOK
		})
}
