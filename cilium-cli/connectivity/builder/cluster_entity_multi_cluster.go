// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

type clusterEntityMultiCluster struct{}

func (t clusterEntityMultiCluster) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("cluster-entity-multi-cluster", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithCiliumPolicy(allowClusterEntityPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-other-node"})),
		).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
