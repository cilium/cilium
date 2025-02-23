// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressL7TlsHeaders struct{}

func (t clientEgressL7TlsHeaders) build(ct *check.ConnectivityTest, templates map[string]string) {
	clientEgressL7TlsHeadersTest(ct, templates, false)
	clientEgressL7ExtraTlsHeadersTest(ct, templates)
	if ct.Features[features.L7PortRanges].Enabled {
		clientEgressL7TlsHeadersTest(ct, templates, true)
	}
}

func clientEgressL7TlsHeadersTest(ct *check.ConnectivityTest, templates map[string]string, portRanges bool) {
	testName := "seq-client-egress-l7-tls-headers"
	yamlFile := templates["clientEgressL7TLSPolicyYAML"]
	if portRanges {
		testName = "seq-client-egress-l7-tls-headers-port-range"
		yamlFile = templates["clientEgressL7TLSPolicyPortRangeYAML"]
	}
	// Test L7 HTTPS interception using an egress policy on the clients.
	newTest(testName, ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretsOnlyFromSecretsNamespace)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretSync)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(yamlFile).                                   // L7 allow policy with TLS interception
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]). // DNS resolution only
		WithScenarios(tests.PodToWorldWithTLSIntercept(
			"-H", "X-Very-Secret-Token: 42",
			"--retry", "5",
			"--retry-delay", "0",
			"--retry-all-errors")).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}

func clientEgressL7ExtraTlsHeadersTest(ct *check.ConnectivityTest, templates map[string]string) {
	testName := "seq-client-egress-l7-extra-tls-headers"
	yamlFile := templates["clientEgressL7TLSPolicyYAML"]
	// Test L7 HTTPS interception using an egress policy on the clients.
	newTest(testName, ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretsOnlyFromSecretsNamespace)).
		WithFeatureRequirements(features.RequireEnabled(features.PolicySecretSync)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget). // Only one certificate for ExternalTarget
		WithCiliumPolicy(yamlFile).                                        // L7 allow policy with TLS interception
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).      // DNS resolution only
		WithScenarios(tests.PodToWorldWithExtraTLSIntercept(
			"externaltarget-tls",
			"-H", "X-Very-Secret-Token: 42",
			"--retry", "5",
			"--retry-delay", "0",
			"--retry-all-errors")).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}
