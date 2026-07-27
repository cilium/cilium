// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
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
// imports a single rule that selects every identity, so all endpoints
// regenerate.
//
// Reported metrics:
//   - ns/update: latency from importer.UpdatePolicy to all endpoints
//     reaching the new revision.
//   - peak_regen_queue: peak number of endpoints in StateWaitingToRegenerate
//     or StateRegenerating during the iteration.
func BenchmarkUpdatePolicyThroughput(b *testing.B) {
	version.Force(testk8s.DefaultVersion)

	for _, numEPs := range []int{100, 1000} {
		for _, numIDs := range []int{10, 100, 1000} {
			if numIDs > numEPs {
				continue
			}
			name := fmt.Sprintf("eps=%d/ids=%d", numEPs, numIDs)
			b.Run(name, func(b *testing.B) {
				runUpdatePolicyBench(b, numEPs, numIDs)
			})
		}
	}
}

func runUpdatePolicyBench(b *testing.B, numEPs, numIDs int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log := hivetest.Logger(b)
	f := newTestFixture(b, log, nil)
	eps := seedEndpoints(b, ctx, f, numEPs, numIDs)

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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule := makeRuleSelectingAllIdentities(numIDs, i)
		require.NoError(b, rule.Sanitize())

		done := make(chan uint64, 1)
		start := time.Now()
		f.importer.UpdatePolicy(&policytypes.PolicyUpdate{
			Rules:    policyutils.RulesToPolicyEntries(api.Rules{rule}),
			Source:   source.CustomResource,
			Resource: ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "default", fmt.Sprintf("bench-%d", i)),
			DoneChan: done,
		})

		var rev uint64
		select {
		case rev = <-done:
		case <-ctx.Done():
			b.Fatalf("policy import timed out at iter %d", i)
		}

		waitForEndpoints(b, ctx, eps, rev)

		b.ReportMetric(float64(time.Since(start).Nanoseconds()), "ns/update")
	}
	b.StopTimer()

	close(stopSampler)
	<-samplerDone
	b.ReportMetric(float64(peakQueue.Load()), "peak_regen_queue")
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
