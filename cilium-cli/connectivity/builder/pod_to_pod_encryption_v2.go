// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

type podToPodEncryptionV2 struct{}

func (t podToPodEncryptionV2) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("pod-to-pod-encryption-v2", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithCondition(func() bool {
			// this test only runs post v1.18.0 clusters
			return versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion)
		}).
		WithScenarios(
			tests.PodToPodEncryptionV2(),
		)

	newTest("pod-to-pod-with-l7-policy-encryption-v2", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithCondition(func() bool {
			// this test only runs post v1.18.0 clusters
			return versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion)
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.EncryptionPod),
		).
		WithCiliumPolicy(clientsEgressL7HTTPFromAnyPolicyYAML).
		WithCiliumPolicy(echoIngressL7HTTPFromAnywherePolicyYAML).
		WithScenarios(
			tests.PodToPodEncryptionV2(),
		)
}
