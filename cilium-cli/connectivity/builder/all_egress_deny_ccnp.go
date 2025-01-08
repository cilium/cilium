// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)


//go:embed manifests/deny-all-egress-ccnp.yaml
var denyAllEgressCCNPPolicyYAML string

type allEgressDenyCCNP struct{}

func (t allEgressDenyCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	//Denying egresses 
	newTest("all-egress-deny-ccnp", ct).
		WithCiliumClusterwidePolicy(denyAllEgressCCNPPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
