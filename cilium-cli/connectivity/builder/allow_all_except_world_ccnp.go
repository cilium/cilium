// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)


//go:embed manifests/allow-all-except-world-ccnp.yaml
var allowAllExceptWorldCCNPYAML string

type allowAllExceptWorldCCNP struct{}

func (t allowAllExceptWorldCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("allow-all-except-world-ccnp", ct).
		WithCiliumClusterwidePolicy(allowAllExceptWorldCCNPYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.ClientToClient(),
			tests.PodToService(),
			tests.PodToHost(),
			tests.PodToExternalWorkload(),
		)
}
