// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type health struct{}

func (t health) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Health check tests.
	newTest("health", ct).
		WithFeatureRequirements(features.RequireEnabled(features.HealthChecking)).
		WithScenarios(tests.CiliumHealth())
}
