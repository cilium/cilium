// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/allow-ingress-specific-ns.yaml
var ingressSpecificNS string

type ingressCNPEgressCCNPMulti struct{}

func (t ingressCNPEgressCCNPMulti) build(ct *check.ConnectivityTest, templates map[string]string) {

	newTest("ingress-cnp-egress-ccnp-multipolicy", ct).
		WithFeatureRequirements(features.RequireEnabled(features.CCNP)).
		WithCiliumClusterwidePolicy(templates["egresstoSpecificNS"]).
		WithCiliumPolicy(ingressSpecificNS).
		WithScenarios(tests.CCNPClienttoClient())

}