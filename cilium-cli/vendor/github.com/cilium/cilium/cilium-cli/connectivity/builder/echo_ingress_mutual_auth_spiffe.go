// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"

	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/echo-ingress-mutual-authentication.yaml
var echoIngressMutualAuthPolicyYAML string

type echoIngressMutualAuthSpiffe struct{}

func (t echoIngressMutualAuthSpiffe) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Test mutual auth with SPIFFE
	newTest("echo-ingress-mutual-auth-spiffe", ct).
		WithCiliumPolicy(echoIngressMutualAuthPolicyYAML).
		WithFeatureRequirements(features.RequireEnabled(features.AuthSpiffe)).
		WithScenarios(tests.PodToPod())
}
