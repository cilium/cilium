// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/perf/benchmarks/netperf"
)

type networkBandwidthLimit struct{}

func (t networkBandwidthLimit) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("network-bandwidth-limit", ct).
		WithCondition(func() bool { return ct.Params().Perf }).
		WithScenarios(netperf.NetBandwidth(""))
}
