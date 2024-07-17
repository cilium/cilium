// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"

	"github.com/cilium/cilium/pkg/versioncheck"
)

type multicast struct{}

func (t multicast) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("multicast", ct).
		WithCondition(func() bool {
			return versioncheck.MustCompile(">=1.16.0")(ct.CiliumVersion)
		}).
		WithCondition(func() bool {
			return ct.Params().IncludeUnsafeTests
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.Multicast),
		).
		WithScenarios(tests.SocatMulticast())
}
