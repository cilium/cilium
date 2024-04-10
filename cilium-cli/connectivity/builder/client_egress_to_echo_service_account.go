// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-service-account.yaml
var clientEgressToEchoServiceAccountPolicyYAML string

type clientEgressToEchoServiceAccount struct{}

func (t clientEgressToEchoServiceAccount) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows port 8080 from client to endpoint with service account label as echo-same-node
	newTest("client-egress-to-echo-service-account", ct).
		WithCiliumPolicy(clientEgressToEchoServiceAccountPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"kind": "client"})),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
