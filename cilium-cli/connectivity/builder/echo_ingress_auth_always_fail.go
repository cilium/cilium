// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-mutual-authentication-fail.yaml
var echoIngressAuthFailPolicyYAML string

type echoIngressAuthAlwaysFail struct{}

func (t echoIngressAuthAlwaysFail) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Test mutual auth with always-fail
	newTest("echo-ingress-auth-always-fail", ct).
		WithCiliumPolicy(echoIngressAuthFailPolicyYAML).
		// this test is only useful when auth is supported in the Cilium version and it is enabled
		// currently this is tested spiffe as that is the only functional auth method
		WithFeatureRequirements(features.RequireEnabled(features.AuthSpiffe)).
		WithScenarios(tests.PodToPod()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultDropAuthRequired
		})
}
