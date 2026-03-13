// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"context"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clusterMeshNSNotGlobal struct{}

func (t clusterMeshNSNotGlobal) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("clustermesh-ns-not-global", ct).
		WithCondition(func() bool { return ct.Params().MultiCluster != "" }).
		WithFeatureRequirements(features.RequireDisabled(features.DefaultGlobalNamespace)).
		WithSetupFunc(func(ctx context.Context, t *check.Test, testCtx *check.ConnectivityTest) error {
			return check.DeployNonGlobalNSTestEnv(ctx, t, testCtx)
		}).
		WithScenarios(tests.ClusterMeshNSNotGlobal()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultDropCurlTimeout, check.ResultNone
		}).
		WithFinalizer(func(ctx context.Context) error {
			return check.CleanupNonGlobalNSTestEnv(ctx, ct)
		})
}
