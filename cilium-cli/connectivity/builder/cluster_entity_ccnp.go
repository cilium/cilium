// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (

	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-cluster-entity-ccnp.yaml
var allowClusterEntityCCNPPolicyYAML string
type clusterEntityCCNP struct{}

func (t clusterEntityCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("cluster-entity-ccnp", ct).
		WithCiliumClusterwidePolicy(allowClusterEntityCCNPPolicyYAML).
		WithScenarios(
			tests.PodToPod(tests.WithDestinationLabelsOption(map[string]string{"name": "echo-same-node"})),
		).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})
}
