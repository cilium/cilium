// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/perf/benchmarks/netperf"
)

type networkPerf struct{}

func (t networkPerf) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("network-perf", ct).
		WithCondition(func() bool { return ct.Params().Perf }).
		WithScenarios(netperf.Netperf(""))
}
