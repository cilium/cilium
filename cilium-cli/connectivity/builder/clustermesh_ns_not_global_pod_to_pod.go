// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/pkg/versioncheck"
)

//go:embed manifests/clustermesh-ns-not-global-deny.yaml
var clusterMeshNSNotGlobalDenyPolicyYAML string

func nonGlobalSupported(ct *check.ConnectivityTest) bool {
	return ct.Params().MultiCluster != "" && versioncheck.MustCompile(">=1.20.0")(ct.CiliumVersion)
}

type clusterMeshNSNotGlobalPodToPod struct{}

func (t clusterMeshNSNotGlobalPodToPod) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-ns-not-global-pod-to-pod", ct).
		WithCondition(func() bool { return nonGlobalSupported(ct) }).
		WithScenarios(tests.ClusterMeshNSNotGlobalPodToPod(check.NonGlobalNSName)).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultOK, check.ResultOK
		})
}

type clusterMeshNSNotGlobalPodToPodDenied struct{}

func (t clusterMeshNSNotGlobalPodToPodDenied) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-ns-not-global-pod-to-pod-denied", ct).
		WithCondition(func() bool { return nonGlobalSupported(ct) }).
		WithCiliumPolicy(clusterMeshNSNotGlobalDenyPolicyYAML).
		WithScenarios(tests.ClusterMeshNSNotGlobalPodToPod(check.NonGlobalDenyNSName)).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			// Dropped at the remote ingress: the client identity is not
			// propagated, so the ingress policy cannot match it.
			return check.ResultOK, check.ResultDefaultDenyIngressDrop
		})
}
