// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type noIpsecXfrmErrors struct{}

func (t noIpsecXfrmErrors) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("no-ipsec-xfrm-errors", ct).
		WithCondition(func() bool { return ct.Params().IncludeConnDisruptTest }).
		WithFeatureRequirements(features.RequireMode(features.EncryptionPod, "ipsec")).
		WithScenarios(tests.NoIPsecXfrmErrors(ct.Params().ExpectedXFRMErrors))
}
