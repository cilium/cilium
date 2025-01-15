// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type podToPodL7 struct{}

func (t podToPodL7) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("pod-to-pod-with-ingress-egress-l7", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(templates["clientEgressL7HTTPPolicyYAML"]).
		WithCiliumPolicy(echoIngressL7HTTPPolicyYAML).
		WithScenarios(tests.PodToPod()).
		WithExpectations(expectation)
}
