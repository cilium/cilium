// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func ClusterMeshNSNotGlobal() check.Scenario {
	return &clusterMeshNSNotGlobal{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type clusterMeshNSNotGlobal struct {
	check.ScenarioBase
}

func (s *clusterMeshNSNotGlobal) Name() string {
	return "clustermesh-ns-not-global"
}

func (s *clusterMeshNSNotGlobal) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	client := ct.RandomClientPod()
	if client == nil {
		t.Fatalf("No client pod available")
	}

	ep := check.HTTPEndpoint(
		"echo-non-global",
		fmt.Sprintf("http://echo-non-global.%s.svc.cluster.local:8080/", check.NonGlobalNSName),
	)

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		t.NewAction(s, fmt.Sprintf("curl-%s", ipFam), client, ep, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, a.CurlCommand(ep))
		})
	})
}
