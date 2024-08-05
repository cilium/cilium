// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type dnsOnly struct{}

func (t dnsOnly) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Only allow UDP:53 to kube-dns, no DNS proxy enabled.
	newTest("dns-only", ct).
		WithCiliumPolicy(clientEgressOnlyDNSPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithScenarios(
			tests.PodToPod(),   // connects to other Pods directly, no DNS
			tests.PodToWorld(), // resolves set domain-name defaults to one.one.one.one
		).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultNone
		})
}
