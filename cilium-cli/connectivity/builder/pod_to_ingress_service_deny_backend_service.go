// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

//go:embed manifests/deny-ingress-backend.yaml
var denyIngressBackendPolicyYAML string

type podToIngressServiceDenyBackendService struct{}

func (t podToIngressServiceDenyBackendService) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-ingress-service-deny-backend-service", ct).
		WithFeatureRequirements(features.RequireEnabled(features.IngressController)).
		WithCiliumPolicy(denyIngressBackendPolicyYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(_ *check.Action) (egress check.Result, ingress check.Result) {
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
