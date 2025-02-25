// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/allow-egress-specific-ns.yaml
var egressfromSpecificNS string

type ingressCCNPEgressCNPMulti struct{}

func (t ingressCCNPEgressCNPMulti) build(ct *check.ConnectivityTest, templates map[string]string) {

	newTest("ingress-ccnp-egress-cnp-multipolicy", ct).
		WithFeatureRequirements(features.RequireEnabled(features.CCNP)).
		WithCiliumClusterwidePolicy(templates["ingressfromSpecificNS"]).
		WithCiliumPolicy(egressfromSpecificNS).
		WithScenarios(tests.CCNPClienttoClient())

}