// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type allowAllWithMetricsCheck struct{}

func (t allowAllWithMetricsCheck) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy allows traffic pod to pod and checks if the metric cilium_forward_count_total increases on cilium agent.
	newTest("allow-all-with-metrics-check", ct).
		WithScenarios(tests.PodToPod()).
		WithExpectations(func(_ *check2.Action) (egress, ingress check2.Result) {
			return check2.ResultOK.ExpectMetricsIncrease(ct.CiliumAgentMetrics(), "cilium_forward_count_total"),
				check2.ResultOK.ExpectMetricsIncrease(ct.CiliumAgentMetrics(), "cilium_forward_count_total")
		})
}
