// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-service-account-ccnp.yaml
var clientEgressToEchoServiceAccountCCNPPolicyYAML string

//go:embed manifests/client-egress-to-echo-service-account-port-range-ccnp.yaml
var clientEgressToEchoServiceAccountCCNPPolicyPortRangeYAML string

type clientEgressToEchoServiceAccountCCNP struct{}

func (t clientEgressToEchoServiceAccountCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoServiceAccountCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoServiceAccountCCNPTest(ct, true)
	}
}

func clientEgressToEchoServiceAccountCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-service-account-ccnp"
	policyYAML := clientEgressToEchoServiceAccountCCNPPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-service-account-port-range-ccnp"
		policyYAML = clientEgressToEchoServiceAccountCCNPPolicyPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(policyYAML).
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
