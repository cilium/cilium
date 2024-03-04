// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-echo.yaml
var clientEgressToEchoPolicyYAML string

type clientEgress struct{}

func (t clientEgress) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows port 8080 from client to echo, so this should succeed
	newTest("client-egress", ct).
		WithCiliumPolicy(clientEgressToEchoPolicyYAML).
		WithScenarios(tests.PodToPod())
}
