// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clusterEntityMultiCluster struct{}

func (t clusterEntityMultiCluster) build(ct *check2.ConnectivityTest, _ map[string]string) {
	newTest("cluster-entity-multi-cluster", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithCiliumPolicy(allowClusterEntityPolicyYAML).
		WithScenarios(
			tests2.PodToPod(tests2.WithDestinationLabelsOption(map[string]string{"name": "echo-other-node"})),
		).
		WithExpectations(func(_ *check2.Action) (egress, ingress check2.Result) {
			return check2.ResultDefaultDenyEgressDrop, check2.ResultNone
		})
}
