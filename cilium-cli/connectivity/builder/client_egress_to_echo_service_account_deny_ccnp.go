// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-service-account-deny-ccnp.yaml
var clientEgressToEchoServiceAccountDenyCCNPPolicyYAML string

//go:embed manifests/client-egress-to-echo-service-account-deny-port-range-ccnp.yaml
var clientEgressToEchoServiceAccountDenyPolicyCCNPPortRangeYAML string

type clientEgressToEchoServiceAccountDenyCCNP struct{}

func (t clientEgressToEchoServiceAccountDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoServiceAccountDenyCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoServiceAccountDenyTest(ct, true)
	}
}

func clientEgressToEchoServiceAccountDenyCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-service-account-deny-ccnp"
	policyYAML := clientEgressToEchoServiceAccountDenyCCNPPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-service-account-deny-port-range-ccnp"
		policyYAML = clientEgressToEchoServiceAccountDenyPolicyCCNPPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).  
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML). 
		WithCiliumClusterwidePolicy(policyYAML).
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
