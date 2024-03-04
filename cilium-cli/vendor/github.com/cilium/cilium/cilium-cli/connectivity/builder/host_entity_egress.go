// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-host-entity-egress.yaml
var allowHostEntityEgressPolicyYAML string

type hostEntityEgress struct{}

func (t hostEntityEgress) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy allows egress traffic towards the host entity
	newTest("host-entity-egress", ct).
		WithCiliumPolicy(allowHostEntityEgressPolicyYAML).
		WithScenarios(tests.PodToHost()).
		WithExpectations(func(_ *check2.Action) (egress, ingress check2.Result) {
			return check2.ResultOK, check2.ResultNone
		})
}
