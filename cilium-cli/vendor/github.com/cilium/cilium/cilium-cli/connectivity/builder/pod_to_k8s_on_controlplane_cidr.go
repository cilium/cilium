// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type podToK8sOnControlplaneCidr struct{}

func (t podToK8sOnControlplaneCidr) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("pod-to-k8s-on-controlplane-cidr", ct).
		WithCondition(func() bool { return ct.Params().K8sLocalHostTest }).
		WithFeatureRequirements(features.RequireEnabled(features.CIDRMatchNodes)).
		WithCiliumPolicy(templates["clientEgressToCIDRK8sPolicyKNPYAML"]).
		WithScenarios(tests.PodToK8sLocal())
}
