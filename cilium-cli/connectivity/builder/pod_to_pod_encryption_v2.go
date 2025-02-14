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
			if !versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion) {
				return false
			}

			// https://github.com/cilium/cilium/actions/runs/13320057239
			if cniChaining, ok := ct.Feature(features.CiliumIPAMMode); !ok || cniChaining.Mode == "aws-cni" {
				return false
			}

			// we run if no encryption is enabled at all to sanity check our
			// tcpdump filters
			encryptionPod, ok := ct.Feature(features.EncryptionPod)
			if !ok {
				return false
			}
			if !encryptionPod.Enabled {
				return true
			}

			// we only run for wireguard right now, until IPsec implements VinE
			if encryptionPod.Mode == "wireguard" {
				return true
			}

			return false
		}).
		WithScenarios(
			tests.PodToPodEncryptionV2(),
		)

	newTest("pod-to-pod-with-l7-policy-encryption-v2", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithCondition(func() bool {
			// this test only runs post v1.18.0 clusters
			if !versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion) {
				return false
			}

			// https://github.com/cilium/cilium/actions/runs/13320057239
			if cniChaining, ok := ct.Feature(features.CiliumIPAMMode); !ok || cniChaining.Mode == "aws-cni" {
				return false
			}

			encryptionPod, ok := ct.Feature(features.EncryptionPod)
			if !ok {
				return false
			}

			// we only run for wireguard right now, until IPsec implements VinE
			if encryptionPod.Mode == "wireguard" {
				return true
			}

			return false
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
