// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type podToPodEncryptionInjection struct{}

func (t podToPodEncryptionInjection) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("pod-to-pod-encryption-injection", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithFeatureRequirements(
			features.RequireEnabled(features.NodeWithoutCilium),
		).
		WithScenarios(
			tests.PodToPodEncryptionInjection(features.RequireEnabled(features.EncryptionPod)),
		)
}
