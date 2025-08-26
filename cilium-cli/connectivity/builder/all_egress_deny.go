// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/deny-all-egress.yaml
var denyAllEgressPolicyYAML string

type allEgressDeny struct{}

func (t allEgressDeny) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy denies all egresses by default
	newTest("all-egress-deny", ct).
		WithCiliumPolicy(denyAllEgressPolicyYAML).
		WithScenarios(
			tests.PodToPod(),
			tests.PodToPodWithEndpoints(),
		).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
