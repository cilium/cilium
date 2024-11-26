// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressTlsSni struct{}

func (t clientEgressTlsSni) build(ct *check.ConnectivityTest, templates map[string]string) {
	clientEgressTlsSniTest(ct, templates)
	clientEgressL7TlsSniTest(ct, templates)
}

func clientEgressTlsSniTest(ct *check.ConnectivityTest, templates map[string]string) {
	testName := "client-egress-tls-sni"
	yamlFile := templates["clientEgressTLSSNIPolicyYAML"]
	// Test TLS SNI enforcement using an egress policy on the clients.
	newTest(testName, ct).
		WithCiliumVersion("!1.14.15 !1.14.16 !1.15.9 !1.15.10 !1.16.2 !1.16.3").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorld()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().Port() == 443 {
				return check.ResultOK, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}

func clientEgressL7TlsSniTest(ct *check.ConnectivityTest, templates map[string]string) {
	testName := "client-egress-l7-tls-headers-sni"
	yamlFile := templates["clientEgressL7TLSSNIPolicyYAML"]
	// Test TLS SNI enforcement using an egress policy on the clients.
	newTest(testName, ct).
		WithCiliumVersion("!1.14.15 !1.14.16 !1.15.9 !1.15.10 !1.16.2 !1.16.3").
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretBackendK8s)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy TLS SNI enforcement
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorldWithTLSIntercept("-H", "X-Very-Secret-Token: 42")).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}
