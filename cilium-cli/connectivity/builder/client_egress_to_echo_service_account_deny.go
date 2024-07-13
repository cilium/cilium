// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-service-account-deny.yaml
var clientEgressToEchoServiceAccountDenyPolicyYAML string

//go:embed manifests/client-egress-to-echo-service-account-deny-port-range.yaml
var clientEgressToEchoServiceAccountDenyPolicyPortRangeYAML string

type clientEgressToEchoServiceAccountDeny struct{}

func (t clientEgressToEchoServiceAccountDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoServiceAccountDenyTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoServiceAccountDenyTest(ct, true)
	}
}

func clientEgressToEchoServiceAccountDenyTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-service-account-deny"
	policyYAML := clientEgressToEchoServiceAccountDenyPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-service-account-deny-port-range"
		policyYAML = clientEgressToEchoServiceAccountDenyPolicyPortRangeYAML
	}
	// This policy denies port 8080 from client to endpoint with service account, but not from client2
	newTest(testName, ct).
		WithCiliumPolicy(allowAllEgressPolicyYAML).  // Allow all egress traffic
		WithCiliumPolicy(allowAllIngressPolicyYAML). // Allow all ingress traffic
		WithCiliumPolicy(policyYAML).
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
