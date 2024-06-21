// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

type noFragmentation struct{}

func (t noFragmentation) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-pod-no-frag", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithScenarios(
			tests.PodToPodNoFrag(),
		)

}
