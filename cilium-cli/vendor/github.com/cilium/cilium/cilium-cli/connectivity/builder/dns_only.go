// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type dnsOnly struct{}

func (t dnsOnly) build(ct *check2.ConnectivityTest, _ map[string]string) {
	// Only allow UDP:53 to kube-dns, no DNS proxy enabled.
	newTest("dns-only", ct).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(
			tests2.PodToPod(),   // connects to other Pods directly, no DNS
			tests2.PodToWorld(), // resolves set domain-name defaults to one.one.one.one
		).
		WithExpectations(func(_ *check2.Action) (egress check2.Result, ingress check2.Result) {
			return check2.ResultDropCurlTimeout, check2.ResultNone
		})
}
