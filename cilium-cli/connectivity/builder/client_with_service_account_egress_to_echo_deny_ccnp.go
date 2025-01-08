// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-with-service-account-egress-to-echo-deny-ccnp.yaml
var clientWithServiceAccountEgressToEchoDenyCCNPPolicyYAML string

//go:embed manifests/client-with-service-account-egress-to-echo-deny-port-range-ccnp.yaml
var clientWithServiceAccountEgressToEchoDenyPolicyCCNPPortRangeYAML string

type clientWithServiceAccountEgressToEchoDenyCCNP struct{}

func (t clientWithServiceAccountEgressToEchoDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientWithServiceAccountEgressToEchoDenyCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientWithServiceAccountEgressToEchoDenyCCNPTest(ct, true)
	}
}

func clientWithServiceAccountEgressToEchoDenyCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-with-service-account-egress-to-echo-deny-ccnp"
	policyYAML := clientWithServiceAccountEgressToEchoDenyCCNPPolicyYAML
	if portRanges {
		testName = "client-with-service-account-egress-to-echo-deny-port-range-ccnp"
		policyYAML = clientWithServiceAccountEgressToEchoDenyPolicyCCNPPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).  
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML). 
		WithCiliumClusterwidePolicy(policyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client"})),  //client -> echo should be denied
			tests.PodToPod(tests.WithSourceLabelsOption(map[string]string{"name": "client2"})), //client2 -> echo should be allowed
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})
}
