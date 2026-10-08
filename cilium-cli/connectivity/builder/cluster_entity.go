// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clusterEntity struct{}

func (t clusterEntity) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows cluster entity
	newTest("cluster-entity", ct).
		WithCiliumPolicy(allowClusterEntityPolicyYAML).
		WithScenarios(
			// Only enable to local cluster for now due to the below
			// https://github.com/cilium/cilium/blob/88c4dddede2a3b5b9a7339c1316a0dedd7229a26/pkg/policy/api/entity.go#L126
			tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-same-node"})),
		).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})
}
