// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type podToIngressService struct{}

func (t podToIngressService) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Test Ingress controller
	newTest("pod-to-ingress-service", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithScenarios(tests.PodToIngress())
}
