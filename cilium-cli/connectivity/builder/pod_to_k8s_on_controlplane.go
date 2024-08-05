// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-entities-k8s.yaml
var clientEgressToEntitiesK8sPolicyYAML string

type podToK8sOnControlplane struct{}

func (t podToK8sOnControlplane) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-k8s-on-controlplane", ct).
		WithCondition(func() bool { return ct.Params().K8sLocalHostTest }).
		WithCiliumPolicy(clientEgressToEntitiesK8sPolicyYAML).
		WithScenarios(tests.PodToK8sLocal())
}
