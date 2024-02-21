// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-entities-world.yaml
var clientEgressToEntitiesWorldPolicyYAML string

type toEntitiesWorld struct{}

func (t toEntitiesWorld) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows UDP to kube-dns and port 80 TCP to all 'world' endpoints.
	newTest("to-entities-world", ct).
		WithCiliumPolicy(clientEgressToEntitiesWorldPolicyYAML).
		WithScenarios(tests.PodToWorld(tests.WithRetryDestPort(80))).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 80 {
				return check.ResultOK, check.ResultNone
			}
			// PodToWorld traffic to port 443 will be dropped by the policy
			return check.ResultDropCurlTimeout, check.ResultNone
		})
}
