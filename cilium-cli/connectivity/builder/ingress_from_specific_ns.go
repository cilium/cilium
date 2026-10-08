// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type ingressfromSpecificNamespace struct{}

func (t ingressfromSpecificNamespace) build(ct *check.ConnectivityTest, templates map[string]string) {

	newTest("ingress-from-specific-namespace-ccnp", ct).
		WithFeatureRequirements(features.RequireEnabled(features.CCNP)).
		WithCiliumClusterwidePolicy(templates["ingressfromSpecificNS"]).
		WithScenarios(tests.CCNPClienttoClient())

}
