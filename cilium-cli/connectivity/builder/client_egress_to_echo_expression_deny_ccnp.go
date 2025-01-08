// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-expression-deny-ccnp.yaml
var clientEgressToEchoExpressionDenyCCNPPolicyYAML string

//go:embed manifests/client-egress-to-echo-expression-deny-port-range-ccnp.yaml
var clientEgressToEchoExpressionDenyCCNPPolicyPortRangeYAML string

type clientEgressToEchoExpressionDenyCCNP struct{}

func (t clientEgressToEchoExpressionDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoExpressionDenyCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoExpressionDenyCCNPTest(ct, true)
	}
}

func clientEgressToEchoExpressionDenyCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-expression-deny-ccnp"
	policyYAML := clientEgressToEchoExpressionDenyCCNPPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-expression-deny-port-range-ccnp"
		policyYAML = clientEgressToEchoExpressionDenyCCNPPolicyPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).  
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML). 
		WithCiliumClusterwidePolicy(policyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)), 
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), 
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") &&
				a.Source().HasLabel("name", "client") {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultOK
		})
}
