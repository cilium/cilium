// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type podToControlplaneHostCidr struct{}

func (t podToControlplaneHostCidr) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Check that pods can access  when referencing them by CIDR selectors
	// (when this feature is enabled).
	newTest("pod-to-controlplane-host-cidr", ct).
		WithCondition(func() bool { return ct.Params().K8sLocalHostTest }).
		WithFeatureRequirements(features.RequireEnabled(features.CIDRMatchNodes)).
		WithK8SPolicy(templates["clientEgressToCIDRCPHostPolicyYAML"]).
		WithScenarios(tests.PodToControlPlaneHost())
}
