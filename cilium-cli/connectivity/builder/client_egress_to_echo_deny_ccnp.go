// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-deny-ccnp.yaml
var clientEgressToEchoDenyCCNPPolicyYAML string

//go:embed manifests/client-egress-to-echo-deny-port-range-ccnp.yaml
var clientEgressToEchoDenyCCNPPolicyPortRangeYAML string

type clientEgressToEchoDenyCCNP struct{}

func (t clientEgressToEchoDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	clientEgressToEchoDenyCCNPTest(ct, false)
	if ct.Features[features.PortRanges].Enabled {
		clientEgressToEchoDenyCCNPTest(ct, true)
	}
}

func clientEgressToEchoDenyCCNPTest(ct *check.ConnectivityTest, portRanges bool) {
	testName := "client-egress-to-echo-deny-ccnp"
	policyYAML := clientEgressToEchoDenyCCNPPolicyYAML
	if portRanges {
		testName = "client-egress-to-echo-deny-port-range-ccnp"
		policyYAML = clientEgressToEchoDenyCCNPPolicyPortRangeYAML
	}
	newTest(testName, ct).
		WithCiliumClusterwidePolicy(allowAllEgressCCNPPolicyYAML).  
		WithCiliumClusterwidePolicy(allowAllIngressCCNPPolicyYAML). 
		WithCiliumClusterwidePolicy(policyYAML).                
		WithScenarios(
			tests.ClientToClient(), 
			tests.PodToPod(),      
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("kind", "client") &&
				a.Destination().HasLabel("kind", "echo") &&
				a.Destination().Port() == 8080 {
				return check.ResultPolicyDenyEgressDrop, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}
