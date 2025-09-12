// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type ipsecKeyDerivation struct{}

func (t ipsecKeyDerivation) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("ipsec-key-derivation-validation", ct).
		WithCiliumVersion(">=1.19.0-pre.0").
		WithCondition(func() bool {
			return ct.Params().IncludeUnsafeTests
		}).
		WithFeatureRequirements(features.RequireMode(features.EncryptionPod, "ipsec")).
		WithScenarios(tests.IPsecKeyDerivationValidation())
}
