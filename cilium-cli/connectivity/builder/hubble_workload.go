// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type hubbleWorkload struct{}

func (hubbleWorkload) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("hubble-workload", ct).
		WithMultiNodeOnly().
		WithCondition(
			func() bool { return ct.Params().MultiCluster == "" },
			"test requires a single cluster",
		).
		WithCondition(
			func() bool { return ct.Params().Hubble },
			"test requires Hubble flow collection",
		).
		WithCondition(
			func() bool { return ct.Params().FlowValidation != check.FlowValidationModeDisabled },
			"test requires Hubble flow validation",
		).
		WithScenarios(tests.HubbleWorkload())
}
