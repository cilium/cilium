// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/allow-host-entity-ingress.yaml
var allowHostEntityIngressPolicyYAML string

type hostEntityIngress struct{}

func (t hostEntityIngress) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows ingress traffic from the host entity
	newTest("host-entity-ingress", ct).
		WithCiliumPolicy(allowHostEntityIngressPolicyYAML).
		WithScenarios(tests.HostToPod())
}
