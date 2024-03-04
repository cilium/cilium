// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-entities-world.yaml
var clientEgressToEntitiesWorldPolicyYAML string

type toEntitiesWorld struct{}

func (t toEntitiesWorld) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy allows UDP to kube-dns and port 80 TCP to all 'world' endpoints.
	newTest("to-entities-world", ct).
		WithCiliumPolicy(clientEgressToEntitiesWorldPolicyYAML).
		WithScenarios(tests2.PodToWorld(tests2.WithRetryDestPort(80))).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Destination().Port() == 80 {
				return check2.ResultOK, check2.ResultNone
			}
			// PodToWorld traffic to port 443 will be dropped by the policy
			return check2.ResultDropCurlTimeout, check2.ResultNone
		})
}
