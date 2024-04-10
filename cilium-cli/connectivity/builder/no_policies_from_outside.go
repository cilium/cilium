// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

type noPoliciesFromOutside struct{}

func (t noPoliciesFromOutside) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-policies-from-outside", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithFeatureRequirements(features.RequireEnabled(features.NodeWithoutCilium)).
		WithIPRoutesFromOutsideToPodCIDRs().
		WithScenarios(tests.FromCIDRToPod())
}
