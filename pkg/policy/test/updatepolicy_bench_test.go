// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	testk8s "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// BenchmarkUpdatePolicyThroughput measures end-to-end policy import latency
// through the real policy importer, compute cell, and endpoint manager
// dispatch, across varying endpoint and unique-identity counts. Each iteration
// replaces a single rule that selects every identity, so all endpoints
// regenerate and every identity's selector policy is replaced.
//
// Reported metrics:
//   - ns/update: mean latency from importer.UpdatePolicy to all endpoints
//     reaching the new revision.
//   - peak_regen_queue: peak number of endpoints in StateWaitingToRegenerate
//     or StateRegenerating during the iteration.
//   - <reason>-regens/update: endpoint regenerations per update, by reason.
//   - memory-growth-B: live heap after the last update, over the live heap
//     after a first, untimed one.
func BenchmarkUpdatePolicyThroughput(b *testing.B) {
	version.Force(testk8s.DefaultVersion)

	for _, numEPs := range []int{100, 1000} {
		for _, numIDs := range []int{10, 100, 1000} {
			if numIDs > numEPs {
				continue
			}
			name := fmt.Sprintf("eps=%d/ids=%d", numEPs, numIDs)
			b.Run(name, func(b *testing.B) {
				runUpdatePolicyBench(b, numEPs, numIDs, 0)
			})
		}
	}
	// Bulky L7 rules, so that a replaced selector policy that stays reachable
	// shows in memory-growth-B.
	b.Run("eps=100/ids=20/http=40", func(b *testing.B) {
		runUpdatePolicyBench(b, 100, 20, 40)
	})
}

func runUpdatePolicyBench(b *testing.B, numEPs, numIDs, httpRules int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	regenerations := newRegenerationCounter(b)
	// The benchmark keeps its log output in memory, which would show in
	// memory-growth-B.
	log := slog.New(slog.DiscardHandler)
	f := newTestFixture(b, log, nil)
	eps := seedEndpoints(b, ctx, f, numEPs, numIDs)

	// update replaces the benchmark's policy with its seed-th version and
	// returns how long the endpoints took to reach it.
	update := func(seed int) time.Duration {
		rule := makeRuleSelectingAllIdentities(numIDs, seed, httpRules)
		require.NoError(b, rule.ValidateAndSanitize())

		done := make(chan uint64, 1)
		start := time.Now()
		f.importer.UpdatePolicy(&policytypes.PolicyUpdate{
			Rules:    policyutils.RulesToPolicyEntries(api.Rules{rule}),
			Source:   source.CustomResource,
			Resource: ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "default", "bench"),
			DoneChan: done,
		})

		var rev uint64
		select {
		case rev = <-done:
		case <-ctx.Done():
			b.Fatalf("policy import timed out at update %d", seed)
		}

		waitForEndpoints(b, ctx, eps, rev)
		return time.Since(start)
	}

	// Measure from after a first update, so that memory-growth-B is what the
	// updates leave behind rather than the cost of having a policy at all.
	update(0)
	settleRegenerations(b, ctx, f.epm, regenerations)
	regensBefore := regenerationsByReason(regenerations)
	heapBefore := liveHeap()

	var peakQueue atomic.Int64
	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		t := time.NewTicker(1 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case <-t.C:
				var q int64
				for _, ep := range eps {
					s := ep.GetState()
					if s == endpoint.StateWaitingToRegenerate || s == endpoint.StateRegenerating {
						q++
					}
				}
				for {
					prev := peakQueue.Load()
					if q <= prev || peakQueue.CompareAndSwap(prev, q) {
						break
					}
				}
			}
		}
	}()

	var total time.Duration
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		total += update(i)
	}
	b.StopTimer()
	b.ReportMetric(float64(total.Nanoseconds())/float64(b.N), "ns/update")

	close(stopSampler)
	<-samplerDone
	b.ReportMetric(float64(peakQueue.Load()), "peak_regen_queue")

	settleRegenerations(b, ctx, f.epm, regenerations)
	for reason, n := range regenerationsByReason(regenerations) {
		b.ReportMetric(float64(n-regensBefore[reason])/float64(b.N), strings.ReplaceAll(reason, " ", "_")+"-regens/update")
	}
	b.ReportMetric(float64(liveHeap())-float64(heapBefore), "memory-growth-B")
}

// waitForEndpoints blocks until every endpoint reaches rev.
func waitForEndpoints(tb testing.TB, ctx context.Context, eps []*endpoint.Endpoint, rev uint64) {
	tb.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, ep := range eps {
		select {
		case <-ep.WaitForPolicyRevision(waitCtx, rev, nil):
		case <-waitCtx.Done():
			tb.Fatalf("endpoint %d did not reach policy revision %d; state=%s identity=%d",
				ep.ID, rev, ep.GetState(), ep.GetIdentity())
		}
	}
}
