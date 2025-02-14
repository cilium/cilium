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

//go:embed manifests/client-egress-l7-http-from-any.yaml
var clientsEgressL7HTTPFromAnyPolicyYAML string

type podToPodEncryption struct{}

func (t podToPodEncryption) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Encryption checks are always executed as a sanity check, asserting whether
	// unencrypted packets shall, or shall not, be observed based on the feature set.
	newTest("pod-to-pod-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithCondition(func() bool {

			// for wireguard, we can run the podToPodEncryptionV2 tests if we
			// are on a post v1.18 cluster and not using aws-cni chaining
			encryptionPod, ok := ct.Feature(features.EncryptionPod)
			if !ok {
				return false
			}
			cniChaining, ok := ct.Feature(features.CNIChaining)
			if !ok {
				return false
			}
			if encryptionPod.Mode == "wireguard" && versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion) && cniChaining.Mode != "aws-cni" {
				return false
			}

			return true
		}).
		WithScenarios(
			tests.PodToPodEncryption(features.RequireEnabled(features.EncryptionPod)),
		)

	newTest("pod-to-pod-with-l7-policy-encryption", ct).
		WithCondition(func() bool { return !ct.Params().SingleNode }).
		WithCondition(func() bool {
			// for wireguard, we can run the podToPodEncryptionV2 tests if we
			// are on a post v1.18 cluster and not using aws-cni chaining
			encryptionPod, ok := ct.Feature(features.EncryptionPod)
			if !ok {
				return false
			}
			cniChaining, ok := ct.Feature(features.CNIChaining)
			if !ok {
				return false
			}
			if encryptionPod.Mode == "wireguard" && versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion) && cniChaining.Mode != "aws-cni" {
				return false
			}

			if ok, _ := ct.Features.MatchRequirements(features.RequireMode(features.EncryptionPod, "ipsec")); ok {
				// Introduced in v1.17.0, backported to v1.15.11 and v1.16.4.
				if !versioncheck.MustCompile(">=1.15.11 <1.16.0 || >=1.16.4")(ct.CiliumVersion) {
					return false
				}
			}
			return true
		}).
		WithFeatureRequirements(
			features.RequireEnabled(features.L7Proxy),
			features.RequireEnabled(features.EncryptionPod),
		).
		WithCiliumPolicy(clientsEgressL7HTTPFromAnyPolicyYAML).
		WithCiliumPolicy(echoIngressL7HTTPFromAnywherePolicyYAML).
		WithScenarios(
			tests.PodToPodEncryption(),
		)
}
