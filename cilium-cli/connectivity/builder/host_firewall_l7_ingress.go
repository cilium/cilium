// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/host-firewall-l7-ingress.yaml
var hostFirewallL7IngressPolicyYAML string

type hostFirewallL7Ingress struct{}

// build verifies that an L7-proxied connection to a pod on a remote node
// completes successfully when the host firewall is enabled and host
// ingress is default-deny. The forward leg is redirected to envoy on the
// destination node; the upstream socket envoy opens to the local pod is
// sourced from the cilium_host IP. Without per-flow CT installed for that
// upstream connection, the reply SYN,ACK from the backend hits the host's
// default-deny ingress and is dropped, causing the curl to fail.
//
// Regression test for https://github.com/cilium/cilium/issues/45565.
func (t hostFirewallL7Ingress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("host-firewall-l7-ingress", ct).
		WithUnsafeTests().
		WithFeatureRequirements(
			features.RequireEnabled(features.HostFirewall),
			features.RequireEnabled(features.L7Proxy),
		).
		WithCiliumClusterwidePolicy(hostFirewallL7IngressPolicyYAML).
		WithCiliumPolicy(echoIngressL7HTTPPolicyYAML).
		WithScenarios(
			tests.PodToPod(
				tests.WithSourceLabelsOption(client2Label),
				tests.WithDestinationLabelsOption(map[string]string{"name": "echo-other-node"}),
			),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			egress = check.ResultOK
			egress.HTTP = check.HTTP{Method: "GET"}
			return egress, check.ResultNone
		})
}
