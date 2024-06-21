// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium-cli/utils/features"
)

//go:embed manifests/client-egress-l7-http-from-any.yaml
var clientsEgressL7HTTPFromAnyPolicyYAML string

type podToPodEncryption struct{}

func (t podToPodEncryption) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("pod-to-pod-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithScenarios(
			tests.PodToPodEncryption(features.RequireEnabled(features.EncryptionPod)),
		)

	newTest("pod-to-pod-with-l7-policy-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			// Once https://github.com/cilium/cilium/issues/33168 is fixed, we
			// can enable for IPsec too.
			features.RequireMode(features.EncryptionPod, "wireguard"),
		).
		WithCiliumPolicy(clientsEgressL7HTTPFromAnyPolicyYAML).
		WithCiliumPolicy(echoIngressL7HTTPFromAnywherePolicyYAML).
		WithScenarios(
			tests.PodToPodEncryption(features.RequireEnabled(features.EncryptionPod)),
		)
}
