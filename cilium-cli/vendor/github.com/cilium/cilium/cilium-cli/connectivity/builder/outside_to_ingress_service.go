// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type outsideToIngressService struct{}

func (t outsideToIngressService) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("outside-to-ingress-service", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.IngressController),
			features.RequireEnabled(features.NodeWithoutCilium)).
		WithScenarios(tests.OutsideToIngressService())
}
