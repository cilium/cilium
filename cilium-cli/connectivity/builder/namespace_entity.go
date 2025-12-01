// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type namespaceEntity struct{}

func (t namespaceEntity) build(ct *check.ConnectivityTest, _ map[string]string) {
	// This policy allows traffic only within the same namespace using
	// the "namespace" entity. Pods with kind=ccnp in any namespace can
	// communicate with other pods in the SAME namespace, but not across
	// namespaces.
	newTest("namespace-entity", ct).
		WithFeatureRequirements(features.RequireEnabled(features.CCNP)).
		WithCiliumClusterwidePolicy(allowIntraNamespaceEntityPolicyYAML).
		WithScenarios(tests.CCNPClienttoClient()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			// When source and destination are in the same namespace,
			// traffic should be allowed. When in different namespaces,
			// traffic should be dropped.
			// Pod.Name() returns "namespace/name", so we extract the namespace
			// from the first part.
			srcName := a.Source().Name()
			dstName := a.Destination().Name()
			srcNS := strings.Split(srcName, "/")[0]
			dstNS := strings.Split(dstName, "/")[0]
			if srcNS == dstNS {
				return check.ResultOK, check.ResultOK
			}
			return check.ResultDrop, check.ResultNone
		})
}
