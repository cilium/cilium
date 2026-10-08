// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-to-echo-no-cluster-policy.yaml
var clientEgressToEchoNoClusterPolicyYAML string

type policyLocalCluster struct{}

func (t policyLocalCluster) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("policy-local-cluster-egress", ct).
		WithCiliumPolicy(clientEgressToEchoNoClusterPolicyYAML).
		WithCiliumPolicy(templates["clientEgressOnlyPort53PolicyYAML"]).
		WithScenarios(tests.PodToPod()).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if !ct.Features[features.PolicyDefaultLocalCLuster].Enabled {
				return check.ResultOK, check.ResultOK
			}
			if ct.Params().MultiCluster == "" {
				return check.ResultOK, check.ResultOK
			}
			if a.Destination().HasLabel("name", "echo-same-node") {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
