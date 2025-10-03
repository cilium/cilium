// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type egresstoSpecificNamespace struct{}

func (t egresstoSpecificNamespace) build(ct *check.ConnectivityTest, templates map[string]string) {

	newTest("egress-to-specific-namespace-ccnp", ct).
		WithFeatureRequirements(features.RequireEnabled(features.CCNP)).
		WithCiliumClusterwidePolicy(templates["egresstoSpecificNS"]).
		WithScenarios(tests.CCNPClienttoClient())

}
