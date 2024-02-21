// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type clientEgressL7TlsHeaders struct{}

func (t clientEgressL7TlsHeaders) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Test L7 HTTPS interception using an egress policy on the clients.
	newTest("client-egress-l7-tls-headers", ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.SecretBackendK8s)).
		WithCABundleSecret().
		WithCertificate("externaltarget-tls", ct.Params().ExternalTarget).
		WithCiliumPolicy(templates["clientEgressL7TLSPolicyYAML"]). // L7 allow policy with TLS interception
		WithScenarios(tests.PodToWorldWithTLSIntercept("-H", "X-Very-Secret-Token: 42")).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultNone
		})
}
