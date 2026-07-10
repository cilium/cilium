// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type podToNodeCidrpolicy struct{}

func (t podToNodeCidrpolicy) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Check that pods can access nodes when referencing them by CIDR selectors
	// (when this feature is enabled).
	newTest("pod-to-node-cidrpolicy", ct).
		WithFeatureRequirements(features.RequireEnabled(features.CIDRMatchNodes)).
		WithK8SPolicy(templates["clientEgressToCIDRNodeKNPYAML"]).
		WithScenarios(tests.PodToHost())
}
