// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type ztunnelPodToPodEncryption struct{}

func (t ztunnelPodToPodEncryption) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("ztunnel-pod-to-pod-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithFeatureRequirements(features.RequireEnabled(features.Ztunnel)).
		WithCondition(func() bool {
			// this test only runs post v1.19.0 clusters
			// return versioncheck.MustCompile(">=1.19.0")(ct.CiliumVersion)
			return true
		}).
		WithScenarios(
			tests.ZTunnelPodToPodEncryption(),
		)
}
