// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type noPoliciesExtra struct{}

func (t noPoliciesExtra) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-policies-extra", ct).
		WithFeatureRequirements(withKPRReqForMultiCluster(ct)...).
		WithScenarios(
			tests.PodToRemoteNodePort(),
			tests.PodToLocalNodePort(),
			tests.PodToLocalNodePortETPLocal(),
		)

	newTest("no-policies-extra-etp-local-remote", ct).
		WithFeatureRequirements(withKPRReqForMultiCluster(ct)...).
		WithMultiNodeOnly().
		WithScenarios(tests.PodToRemoteNodePortETPLocal()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			// The remote NodePort node has no local endpoint for this Service.
			return check.ResultDrop, check.ResultNone
		})
}
