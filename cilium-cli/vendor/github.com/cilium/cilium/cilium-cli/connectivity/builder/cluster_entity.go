// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clusterEntity struct{}

func (t clusterEntity) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy allows cluster entity
	newTest("cluster-entity", ct).
		WithCiliumPolicy(allowClusterEntityPolicyYAML).
		WithScenarios(
			// Only enable to local cluster for now due to the below
			// https://github.com/cilium/cilium/blob/88c4dddede2a3b5b9a7339c1316a0dedd7229a26/pkg/policy/api/entity.go#L126
			tests2.PodToPod(tests2.WithDestinationLabelsOption(map[string]string{"name": "echo-same-node"})),
		).
		WithExpectations(func(_ *check2.Action) (egress, ingress check2.Result) {
			return check2.ResultOK, check2.ResultOK
		})
}
