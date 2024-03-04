// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type podToPodEncryption struct{}

func (t podToPodEncryption) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("pod-to-pod-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithScenarios(
			tests.PodToPodEncryption(features.RequireEnabled(features.EncryptionPod)),
		)
}
