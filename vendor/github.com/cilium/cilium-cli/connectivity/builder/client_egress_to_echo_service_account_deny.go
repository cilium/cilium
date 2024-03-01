// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-service-account-deny.yaml
var clientEgressToEchoServiceAccountDenyPolicyYAML string

type clientEgressToEchoServiceAccountDeny struct{}

func (t clientEgressToEchoServiceAccountDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies port 8080 from client to endpoint with service account, but not from client2
	newTest("client-egress-to-echo-service-account-deny", ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(clientEgressToEchoServiceAccountDenyPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})
}
