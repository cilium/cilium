// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"context"
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
		WithSetupFunc(func(ctx context.Context, t *check.Test, testCtx *check.ConnectivityTest) error {
			return check.DeployZtunnelTestEnv(ctx, t, testCtx)
		}).
		WithScenarios(
			tests.ZTunnelEnrolledToEnrolledSameNode(),
			tests.ZTunnelEnrolledToEnrolledDifferentNode(),
			tests.ZTunnelUnenrolledToUnenrolledSameNode(),
			tests.ZTunnelUnenrolledToUnenrolledDifferentNode(),
			tests.ZTunnelEnrolledToUnenrolledSameNode(),
			tests.ZTunnelEnrolledToUnenrolledDifferentNode(),
			tests.ZTunnelUnenrolledToEnrolledSameNode(),
			tests.ZTunnelUnenrolledToEnrolledDifferentNode(),
			tests.ZTunnelEnrolledToEnrolledCrossNamespaceSameNode(),
			tests.ZTunnelEnrolledToEnrolledCrossNamespaceDifferentNode(),
			tests.ZTunnelUnenrolledToEnrolledCrossNamespaceSameNode(),
			tests.ZTunnelUnenrolledToEnrolledCrossNamespaceDifferentNode(),
		)
}
