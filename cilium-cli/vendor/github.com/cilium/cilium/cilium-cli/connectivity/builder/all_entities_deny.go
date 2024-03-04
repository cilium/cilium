// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/deny-all-entities.yaml
var denyAllEntitiesPolicyYAML string

type allEntitiesDeny struct{}

func (t allEntitiesDeny) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// This policy denies all entities by default
	newTest("all-entities-deny", ct).
		WithCiliumPolicy(denyAllEntitiesPolicyYAML).
		WithScenarios(
			tests2.PodToPod(),
			tests2.PodToCIDR(),
		).
		WithExpectations(func(_ *check2.Action) (egress, ingress check2.Result) {
			return check2.ResultPolicyDenyEgressDrop, check2.ResultNone
		})
}
