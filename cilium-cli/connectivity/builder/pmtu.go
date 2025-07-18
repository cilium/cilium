// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/pmtu.yaml
var pathMTUPolicy string

type pathMTU struct{}

func (t pathMTU) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("pmtu", ct).
		WithCiliumVersion(">=1.18.0").
		WithCiliumPolicy(pathMTUPolicy).
		WithScenarios(tests.PathMTU())
}
