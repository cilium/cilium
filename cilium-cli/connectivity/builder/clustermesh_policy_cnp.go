// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clusterMeshPolicyCNPIngress struct{}

func (clusterMeshPolicyCNPIngress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-policy-cnp-ingress", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithCiliumPolicy(echoIngressFromOtherClientPolicyYAML).
		WithScenarios(tests.PodToPod(tests.WithCrossClusterOnly())).
		WithExpectations(echoIngressExpectations)
}

type clusterMeshPolicyCNPEgress struct{}

func (clusterMeshPolicyCNPEgress) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-policy-cnp-egress", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithCiliumPolicy(clientEgressToEchoPolicyYAML).
		WithScenarios(tests.PodToPod(tests.WithCrossClusterOnly()))
}

type clusterMeshPolicyCNPIngressL7 struct{}

func (clusterMeshPolicyCNPIngressL7) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-policy-cnp-ingress-l7", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(echoIngressL7HTTPPolicyYAML).
		WithScenarios(tests.PodToPodWithEndpoints(tests.WithCrossClusterOnly())).
		WithExpectations(echoIngressL7Expectations)
}

type clusterMeshPolicyCNPEgressL7 struct{}

func (clusterMeshPolicyCNPEgressL7) build(ct *check.ConnectivityTest, templates map[string]string) {
	newTest("clustermesh-policy-cnp-egress-l7", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireDisabled(features.RHEL)).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithCiliumPolicy(templates["clientEgressL7HTTPPolicyYAML"]).
		WithScenarios(tests.PodToPod(tests.WithCrossClusterOnly())).
		WithExpectations(clientEgressL7Expectations(ct))
}
