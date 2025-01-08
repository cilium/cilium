// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-host-entity-ingress-ccnp.yaml
var allowHostEntityIngressCCNPPolicyYAML string

type hostEntityIngressCCNP struct{}

func (t hostEntityIngressCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	
	newTest("host-entity-ingress-ccnp", ct).
		WithCiliumClusterwidePolicy(allowHostEntityIngressCCNPPolicyYAML).
		WithScenarios(tests.HostToPod())
}
