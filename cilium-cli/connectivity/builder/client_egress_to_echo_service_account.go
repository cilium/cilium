// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-service-account.yaml
var clientEgressToEchoServiceAccountPolicyYAML string

//go:embed manifests/client-egress-to-echo-service-account-port-range.yaml
var clientEgressToEchoServiceAccountPolicyPortRangeYAML string

type clientEgressToEchoServiceAccount struct{}

func (t clientEgressToEchoServiceAccount) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoServiceAccountTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoServiceAccountTest(ct, true)
	}
}

func clientEgressToEchoServiceAccountTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-service-account"
	policyYAML := clientEgressToEchoServiceAccountPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-service-account-port-range"
		policyYAML = clientEgressToEchoServiceAccountPolicyPortRangeYAML
	}
	// This policy allows port 8080 from client to endpoint with service account label as echo-same-node
	newTest(testName, ct).
		WithCiliumPolicy(policyYAML).
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
