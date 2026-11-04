// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

const benchAppLabel = "bench-app"

// benchNamespaceLabel is the namespace label of every identity seeded by
// seedEndpoints.
var benchNamespaceLabel = labels.NewLabel(k8sConst.PodNamespaceLabel, "default", labels.LabelSourceK8s)

// benchIdentityLabels returns the label set used for identity i.
func benchIdentityLabels(i int) labels.LabelArray {
	return labels.LabelArray{
		benchNamespaceLabel,
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

// makeRuleSelectingAllIdentities returns a rule that selects every identity
// seeded by seedEndpoints and allows egress to all of them, through httpRules
// HTTP rules on port 80 if httpRules is not 0. The seed keeps the rule label
// unique across iterations so successive UpdatePolicy calls are distinct
// imports.
func makeRuleSelectingAllIdentities(numIdentities, seed, httpRules int) *api.Rule {
	selectors := make([]api.EndpointSelector, numIdentities)
	for i := range numIdentities {
		selectors[i] = api.NewESFromLabels(
			labels.NewLabel(benchAppLabel, fmt.Sprintf("id-%d", i), labels.LabelSourceK8s),
		)
	}

	egress := api.EgressRule{EgressCommonRule: api.EgressCommonRule{ToEndpoints: selectors}}
	if httpRules > 0 {
		port := api.PortRule{
			Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
			Rules: &api.L7Rules{},
		}
		for i := range httpRules {
			port.Rules.HTTP = append(port.Rules.HTTP, api.PortRuleHTTP{
				Method: "GET",
				Path:   fmt.Sprintf("/api/v1/resource-%d/[a-z0-9]+", i),
				Host:   fmt.Sprintf("svc-%d.example.com", i),
			})
		}
		egress.ToPorts = api.PortRules{port}
	}
	return &api.Rule{
		EndpointSelector: api.NewESFromLabels(benchNamespaceLabel),
		Egress:           []api.EgressRule{egress},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, fmt.Sprintf("bench-rule-%d", seed), labels.LabelSourceAny),
		},
	}
}

// newRegenerationCounter replaces the global endpoint_regenerations_total
// metric with a fresh counter for the duration of tb, so tb must not run in
// parallel with other tests.
func newRegenerationCounter(tb testing.TB) prometheus.Collector {
	orig := metrics.EndpointRegenerationTotal
	regenerations := metric.NewCounterVec(metric.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "endpoint_regenerations_total",
	}, []string{metrics.LabelReason, metrics.LabelOutcome, metrics.LabelError})
	metrics.EndpointRegenerationTotal = regenerations
	tb.Cleanup(func() { metrics.EndpointRegenerationTotal = orig })
	return regenerations
}

// regenerationsByReason sums the completed regenerations in c by reason.
// Failed ones are counted as "<reason>/fail".
func regenerationsByReason(c prometheus.Collector) map[string]uint64 {
	ch := make(chan prometheus.Metric)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	counts := make(map[string]uint64)
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			continue
		}
		var reason, outcome string
		for _, l := range pb.GetLabel() {
			switch l.GetName() {
			case metrics.LabelReason:
				reason = l.GetValue()
			case metrics.LabelOutcome:
				outcome = l.GetValue()
			}
		}
		if outcome == metrics.LabelValueOutcomeFail {
			reason += "/fail"
		}
		counts[reason] += uint64(pb.GetCounter().GetValue())
	}
	return counts
}

// settleRegenerations waits until every endpoint is ready and no regeneration
// in regenerations has completed for 50ms, so that regenerations queued but not
// waited for are counted.
func settleRegenerations(tb testing.TB, ctx context.Context, epm endpointmanager.EndpointManager, regenerations prometheus.Collector) {
	tb.Helper()
	var counts map[string]uint64
	err := waitSettled(ctx, 50*time.Millisecond, func() error {
		prev := counts
		counts = regenerationsByReason(regenerations)
		notReady := func(ep *endpoint.Endpoint) bool { return ep.GetState() != endpoint.StateReady }
		if slices.ContainsFunc(epm.GetEndpoints(), notReady) {
			return errors.New("not all endpoints are ready")
		}
		if !maps.Equal(counts, prev) {
			return errors.New("regeneration counts changed")
		}
		return nil
	})
	require.NoError(tb, err, "endpoints did not settle")
}

// waitSettled waits until check has returned nil continuously for settle. On
// timeout it returns the context error joined with the last check error.
func waitSettled(ctx context.Context, settle time.Duration, check func() error) error {
	var stableSince time.Time
	for {
		err := check()
		switch {
		case err != nil:
			stableSince = time.Time{}
		case stableSince.IsZero():
			stableSince = time.Now()
		}
		if err == nil && time.Since(stableSince) >= settle {
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// liveHeap returns the live heap after a GC.
func liveHeap() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}
