// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type nodeToNodeEncryption struct{}

func (t nodeToNodeEncryption) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("node-to-node-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithScenarios(
			tests.NodeToNodeEncryption(
				features.RequireEnabled(features.EncryptionPod),
				features.RequireEnabled(features.EncryptionNode),
			),
		)
}
