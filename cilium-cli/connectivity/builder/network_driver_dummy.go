// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// networkDriverDummy runs sequentially: its scenarios allocate every dummy
// device published on a node.
type networkDriverDummy struct{}

func (t networkDriverDummy) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("network-driver-dummy", ct).
		WithCiliumVersion(">=1.21.0-0").
		WithFeatureRequirements(features.RequireEnabled(features.NetworkDriver)).
		WithScenarios(tests.NetworkDriverDummy()...)
}
