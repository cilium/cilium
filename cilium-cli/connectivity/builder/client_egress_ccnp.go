// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo-ccnp.yaml
var clientEgressToEchoCCNPPolicyYAML string

type clientEgressCCNP struct{}

func (t clientEgressCCNP) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("client-egress-ccnp", ct).
		WithCiliumClusterwidePolicy(clientEgressToEchoCCNPPolicyYAML).
		WithScenarios(tests.PodToPod())
}
