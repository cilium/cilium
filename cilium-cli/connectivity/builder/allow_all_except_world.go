// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-all-except-world.yaml
var allowAllExceptWorldPolicyYAML string

type allowAllExceptWorld struct{}

func (t allowAllExceptWorld) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Test with an allow-all-except-world (and unmanaged) policy.
	newTest("allow-all-except-world", ct).
		WithCiliumPolicy(allowAllExceptWorldPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.ClientToClient(),
			tests.PodToService(),
			// We are skipping the following checks because NodePort is
			// intended to be used for N-S traffic, which conflicts with
			// policies. See GH-17144.
			// tests.PodToRemoteNodePort(),
			// tests.PodToLocalNodePort(),
			tests.PodToHost(),
			tests.PodToExternalWorkload(),
		)
}
