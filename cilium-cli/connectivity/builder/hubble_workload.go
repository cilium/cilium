// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type hubbleWorkload struct{}

func (hubbleWorkload) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("hubble-workload", ct).
		WithMultiNodeOnly().
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
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
		WithCiliumPolicy(clientsEgressL7HTTPFromAnyPolicyYAML).
		WithCiliumPolicy(echoIngressL7HTTPFromAnywherePolicyYAML).
		WithScenarios(tests.HubbleWorkload())
}
