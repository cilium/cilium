// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-service-account.yaml
var clientEgressToEchoServiceAccountPolicyYAML string

type clientEgressToEchoServiceAccount struct{}

func (t clientEgressToEchoServiceAccount) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy allows port 8080 from client to endpoint with service account label as echo-same-node
	newTest("client-egress-to-echo-service-account", ct).
		WithCiliumPolicy(clientEgressToEchoServiceAccountPolicyYAML).
		WithScenarios(
			tests2.PodToPod(tests2.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check2.ResultOK, check2.ResultOK
			}
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}
