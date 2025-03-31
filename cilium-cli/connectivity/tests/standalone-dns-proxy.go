// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func StandaloneDNSProxy() check.Scenario {

	return &standaloneDNSProxy{}
}

type standaloneDNSProxy struct {
	check.ScenarioBase
}

func (s *standaloneDNSProxy) Name() string {
	return "standalone-dns-proxy"
}

func (s *standaloneDNSProxy) Run(ctx context.Context, t *check.Test) {
	extTarget := t.Context().Params().ExternalTarget
	http := check.HTTPEndpoint(extTarget+"-http", "http://"+extTarget)

	ct := t.Context()

	for _, client := range ct.ClientPods() {
		t.NewAction(s, fmt.Sprintf("nsLookUp-%s", extTarget), &client, http, features.IPFamilyV4).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.NSLookupCommandService(http, features.IPFamilyV4))
		})
	}
}
