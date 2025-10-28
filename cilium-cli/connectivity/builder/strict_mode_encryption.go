// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

type strictModeEncryption struct{}

func (t strictModeEncryption) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("strict-mode-encryption", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		// Until https://github.com/cilium/cilium/pull/35454 is backported to <1.17.0
		WithCiliumVersion(">=1.17.0 <1.18.0").
		WithFeatureRequirements(
			features.RequireEnabled(features.EncryptionStrictMode),
			// Strict mode is only supported with WireGuard
			features.RequireMode(features.EncryptionPod, "wireguard"),
			// Strict mode always allows host-to-host tunnel traffic
			features.RequireDisabled(features.Tunnel),
		).
		WithScenarios(tests.PodToPodMissingIPCache()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultEgressUnencryptedDrop, check.ResultEgressUnencryptedDrop
		})

	newTest("strict-mode-encryption-v2", ct).
		WithCondition(func() bool { return ct.Params().IncludeUnsafeTests }).
		WithCiliumVersion(">=1.18.0").
		WithFeatureRequirements(
			features.RequireEnabled(features.EncryptionStrictMode),
			features.RequireEnabled(features.EncryptionPod),
			// Strict mode always allows host-to-host tunnel traffic
			features.RequireDisabled(features.Tunnel),
		).
		WithCondition(func() bool {
			if ok, _ := ct.Features.MatchRequirements(features.RequireMode(features.EncryptionPod, "ipsec")); ok {
				if !versioncheck.MustCompile(">=1.19.0")(ct.CiliumVersion) {
					return false
				}
			}
			return true
		}).
		WithScenarios(tests.PodToPodMissingIPCacheV2()).
		WithExpectations(func(_ *check.Action) (egress, ingress check.Result) {
			return check.ResultEgressUnencryptedDrop, check.ResultEgressUnencryptedDrop
		})
}
