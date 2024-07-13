// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type noUnexpectedPacketDrops struct{}

func (t noUnexpectedPacketDrops) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-unexpected-packet-drops", ct).
		WithScenarios(tests.NoUnexpectedPacketDrops(ct.Params().ExpectedDropReasons)).
		WithSysdumpPolicy(check.SysdumpPolicyOnce)
}
