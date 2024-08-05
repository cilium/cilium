// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clusterMeshEndpointSliceSync struct{}

func (t clusterMeshEndpointSliceSync) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-endpointslice-sync", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithFeatureRequirements(features.RequireEnabled(features.ClusterMeshEnableEndpointSync)).
		WithScenarios(tests.ClusterMeshEndpointSliceSync())
}
