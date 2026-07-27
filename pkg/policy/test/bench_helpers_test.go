// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

const benchAppLabel = "bench-app"

// benchIdentityLabels returns the label set used for identity i.
func benchIdentityLabels(i int) labels.LabelArray {
	return labels.LabelArray{
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
		labels.NewLabel(benchAppLabel, fmt.Sprintf("id-%d", i), labels.LabelSourceK8s),
	}
}

// seedEndpoints allocates numIdentities identities and creates numEPs
// endpoints, assigning identities round-robin.
func seedEndpoints(tb testing.TB, ctx context.Context, f *testFixture, numEPs, numIdentities int) []*endpoint.Endpoint {
	tb.Helper()
	require.Positive(tb, numIdentities)
	require.Positive(tb, numEPs)

	ids := make([]*identity.Identity, numIdentities)
	for i := range numIdentities {
		id, _, err := f.allocator.AllocateIdentity(ctx, benchIdentityLabels(i).Labels(), true, identity.NumericIdentity(0))
		require.NoError(tb, err)
		ids[i] = id
	}

	eps := make([]*endpoint.Endpoint, numEPs)
	for i := range numEPs {
		ep := f.templateEP.CopyFromTemplate()
		require.NoError(tb, f.epm.AddEndpoint(ep))
		id := ids[i%numIdentities]
		_ = ep.UpdateLabels(ctx, labels.LabelSourceAny, id.Labels, nil, true)
		eps[i] = ep
	}

	// Wait for the initial regeneration from UpdateLabels to advance
	// policyRevision past 0, otherwise a later UpdatePolicy hits the new-endpoint
	// early return and the endpoint stays at an old revision.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, ep := range eps {
		select {
		case <-ep.WaitForPolicyRevision(waitCtx, 1, nil):
		case <-waitCtx.Done():
			tb.Fatalf("endpoint %d did not reach initial policy revision; state=%s identity=%d",
				ep.ID, ep.GetState(), ep.GetIdentity())
		}
	}
	return eps
}

// makeRuleSelectingAllIdentities returns a rule whose EndpointSelector matches
// every identity seeded by seedEndpoints. The seed keeps the rule label unique
// across iterations so successive UpdatePolicy calls are distinct imports.
func makeRuleSelectingAllIdentities(numIdentities, seed int) *api.Rule {
	selectors := make([]api.EndpointSelector, numIdentities)
	for i := range numIdentities {
		selectors[i] = api.NewESFromLabels(
			labels.NewLabel(benchAppLabel, fmt.Sprintf("id-%d", i), labels.LabelSourceK8s),
		)
	}

	return &api.Rule{
		EndpointSelector: selectors[0],
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{ToEndpoints: selectors},
		}},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, fmt.Sprintf("bench-rule-%d", seed), labels.LabelSourceAny),
		},
	}
}
