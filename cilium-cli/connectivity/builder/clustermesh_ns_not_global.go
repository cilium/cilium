// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type clusterMeshNSNotGlobal struct{}

func (t clusterMeshNSNotGlobal) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-ns-not-global", ct).
		WithCondition(func() bool { return nonGlobalSupported(ct) }).
		WithScenarios(tests.ClusterMeshNSNotGlobal()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			// Service not synced: the local frontend has no backends, so the
			// request is dropped at egress.
			return check.ResultAnyReasonEgressDrop, check.ResultNone
		})
}
