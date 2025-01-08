// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-host-entity-egress-ccnp.yaml
var allowHostEntityEgressCCNPPolicyYAML string

type hostEntityEgressCCNP struct{}

func (t hostEntityEgressCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("host-entity-egress-ccnp", ct).
		WithCiliumClusterwidePolicy(allowHostEntityEgressCCNPPolicyYAML).
		WithScenarios(tests.PodToHost()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}
