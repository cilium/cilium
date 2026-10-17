// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
)

// newRegenTestEndpoint returns an endpoint that regenerateBPF can run on up to
// the point where it needs a policy map.
func newRegenTestEndpoint(t *testing.T, repo *policy.Repository, endpointPolicy *policy.EndpointPolicy) *Endpoint {
	ep := &Endpoint{
		aliveCtx:                   t.Context(),
		orchestrator:               &fakeendpoint.FakeOrchestrator{},
		compilationLock:            &lock.RWMutex{},
		policyRepo:                 repo,
		dnsRulesAPI:                noopDNSRulesAPI{},
		desiredPolicy:              endpointPolicy,
		realizedPolicy:             endpointPolicy,
		initialEnvoyPolicyComputed: make(chan struct{}),
		ctCleaned:                  true,
	}
	ep.logger.Store(hivetest.Logger(t))
	return ep
}

func TestRegenerateBPFFailureReverts(t *testing.T) {
	endpointPolicy := &policy.EndpointPolicy{}
	ep := newRegenTestEndpoint(t, &policy.Repository{}, endpointPolicy)
	datapath := &datapathRegenerationContext{
		policyResult: &policyGenerateResult{endpointPolicy: endpointPolicy},
		ctCleaned:    make(chan struct{}),
	}
	var callbackErr error
	// Queue asynchronous work before pre-compilation fails.
	ep.dnsRulesAPI = noopDNSRulesAPI{onRead: func() {
		datapath.proxyWaitGroup.AddCompletionWithCallback(nil, func(err error) { callbackErr = err })
	}}
	var reverted bool
	datapath.revertibles.AddRevert(func() error {
		require.ErrorIs(t, callbackErr, context.Canceled, "pending callbacks must finish before rollback")
		reverted = true
		return nil
	})

	ep.buildMutex.Lock()
	defer ep.buildMutex.Unlock()
	_, err := ep.regenerateBPF(&regenerationContext{
		parentContext:               t.Context(),
		datapathRegenerationContext: datapath,
	})
	require.ErrorContains(t, err, "endpoint has nil policyMapFactory")
	require.True(t, reverted)
}

// An endpoint's first regeneration reuses the policy that ComputeInitialPolicy
// computed, unless the endpoint's identity or the policy changed in between.
func TestFirstRegenerationComputesPolicyOnce(t *testing.T) {
	f := newPolicyTestFixture(t)
	otherID := identity.NewIdentity(f.podID.ID+1, labels.Labels{"other": labels.NewLabel("k8s:other", "", "")})
	f.idManager.Add(otherID)

	for _, tc := range []struct {
		name       string
		change     func(t *testing.T, ep *Endpoint)
		recomputed bool
	}{
		{"unchanged", func(*testing.T, *Endpoint) {}, false},
		{"policy changed", func(t *testing.T, ep *Endpoint) {
			_, err := f.polComputer.RecomputeIdentityPolicyForAllIdentities(f.repo.BumpRevision())
			require.NoError(t, err)
		}, true},
		{"labels changed", func(_ *testing.T, ep *Endpoint) {
			ep.identityRevision++
		}, true},
		{"identity changed", func(t *testing.T, ep *Endpoint) {
			ep.SecurityIdentity = otherID
			computePolicyForEPAndWait(t, ep, f.polComputer, f.repo.GetRevision())
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := newRegenTestEndpoint(t, f.repo, policy.NewEndpointPolicy(hivetest.Logger(t), f.repo))
			ep.policyFetcher = f.polComputer
			ep.SecurityIdentity = f.podID
			ep.Options = option.NewIntOptions(&EndpointMutableOptionLibrary)
			computePolicyForEPAndWait(t, ep, f.polComputer, f.repo.GetRevision())

			regenCtx := &regenerationContext{
				parentContext:               t.Context(),
				datapathRegenerationContext: &datapathRegenerationContext{ctCleaned: make(chan struct{})},
			}
			err, release := ep.ComputeInitialPolicy(regenCtx)
			require.NoError(t, err)
			defer release()
			require.NotNil(t, regenCtx.datapathRegenerationContext.policyResult, "initial policy was not computed")

			tc.change(t, ep)

			// runPreCompilationSteps times the policy calculation only when it
			// does not reuse the initial result.
			regenCtx.Stats = regenerationStatistics{}
			func() {
				ep.buildMutex.Lock()
				defer ep.buildMutex.Unlock()
				_, err = ep.regenerateBPF(regenCtx)
			}()
			// The regeneration gets past the policy step and fails once it
			// needs a policy map.
			require.ErrorContains(t, err, "endpoint has nil policyMapFactory")
			require.Equal(t, tc.recomputed, regenCtx.Stats.policyCalculation.Total() > 0)
		})
	}
}

func TestWaitForProxyCompletionsDrainsRejectedUpdates(t *testing.T) {
	nackErr := errors.New("proxy rejected update")
	tests := []struct {
		name   string
		cancel bool
		err    error
	}{
		{name: "nack", err: nackErr},
		{name: "parent-canceled", cancel: true, err: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &Endpoint{}
			ep.logger.Store(hivetest.Logger(t))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wg := completion.NewWaitGroup(ctx)
			defer wg.Cancel()
			var callbackErr error
			wg.AddCompletionWithCallback(nil, func(err error) { callbackErr = err })
			wg.AddCompletionWithCallback(nil, nil).Complete(nackErr)
			if tt.cancel {
				cancel()
			}

			require.ErrorIs(t, ep.waitForProxyCompletions(ctx, wg), tt.err)
			if tt.cancel {
				// Regeneration drains an early return before reverting resources.
				wg.Cancel()
			}
			require.ErrorIs(t, callbackErr, context.Canceled)
		})
	}
}

func TestWriteInformationalComments(t *testing.T) {
	s := setupEndpointSuite(t)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := createEndpointParams(t, s.orchestrator, s.repo, s.fetcher)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)

	e.Start(uint16(model.ID))
	t.Cleanup(e.Stop)

	var f bytes.Buffer
	err = e.writeInformationalComments(&f)
	require.NoError(t, err)
}

type writeFunc func(io.Writer) error

func BenchmarkWriteHeaderfile(b *testing.B) {
	testutils.IntegrationTest(b)

	s := setupEndpointSuite(b)

	model := newTestEndpointModel(100, StateWaitingForIdentity)
	p := createEndpointParams(b, s.orchestrator, s.repo, s.fetcher)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(b, err)

	e.Start(uint16(model.ID))
	b.Cleanup(e.Stop)

	configWriter := &linuxConfig.HeaderfileWriter{}

	targetComments := func(w io.Writer) error {
		return e.writeInformationalComments(w)
	}
	targetConfig := func(w io.Writer) error {
		return configWriter.WriteEndpointConfig(w, e)
	}

	var buf bytes.Buffer
	memoryBacked := func() (io.Writer, func() error) {
		return &buf, func() error { buf.Reset(); return nil }
	}

	f, err := os.CreateTemp("", "cilium_ep_bench_")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	fileBacked := func() (io.Writer, func() error) {
		return f, func() error {
			_, err := f.Seek(0, io.SeekStart)
			return err
		}
	}

	benchmarks := []struct {
		name       string
		outputFunc func() (io.Writer, func() error)
		write      writeFunc
	}{
		{"in-memory-info", memoryBacked, targetComments},
		{"in-memory-cfg", memoryBacked, targetConfig},
		{"to-disk-info", fileBacked, targetComments},
		{"to-disk-cfg", fileBacked, targetConfig},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			output, reset := bm.outputFunc()
			// Prewarn caches, buffers and the golang JSON marshaller. Since we use b.Loop() this will not be counted
			if err := bm.write(output); err != nil {
				b.Fatal(err)
			}

			for b.Loop() {
				// Reset buffer/file offset to avoid allocating unbounded amounts of memory or disk
				if err := reset(); err != nil {
					b.Fatal(err)
				}
				if err := bm.write(output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
