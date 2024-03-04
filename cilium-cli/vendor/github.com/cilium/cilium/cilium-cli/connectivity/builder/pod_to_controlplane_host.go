// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-egress-to-entities-host.yaml
var clientEgressToEntitiesHostPolicyYAML string

type podToControlplaneHost struct{}

func (t podToControlplaneHost) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pod-to-controlplane-host", ct).
		WithCondition(func() bool { return ct.Params().K8sLocalHostTest }).
		WithCiliumPolicy(clientEgressToEntitiesHostPolicyYAML).
		WithScenarios(tests.PodToControlPlaneHost())
}
