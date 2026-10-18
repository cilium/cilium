// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestRegenerateBPFFailureReverts(t *testing.T) {
	endpointPolicy := &policy.EndpointPolicy{}
	ep := &Endpoint{
		aliveCtx:                   t.Context(),
		orchestrator:               &fakeendpoint.FakeOrchestrator{},
		compilationLock:            &lock.RWMutex{},
		policyRepo:                 &policy.Repository{},
		dnsRulesAPI:                noopDNSRulesAPI{},
		desiredPolicy:              endpointPolicy,
		realizedPolicy:             endpointPolicy,
		initialEnvoyPolicyComputed: make(chan struct{}),
		ctCleaned:                  true,
	}
	ep.logger.Store(hivetest.Logger(t))
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

type recordingAckRedirectProxy struct {
	FakeEndpointProxy
	redirects map[string]uint16
	err       error
}

func (p *recordingAckRedirectProxy) AckRedirects(_ context.Context, redirects map[string]uint16) error {
	p.redirects = redirects
	return p.err
}

func TestWaitForProxyCompletions(t *testing.T) {
	f := newPolicyTestFixture(t)
	selectorPolicy := computeSelectorPolicy(t, f, "proxy-wait")
	nackErr := errors.New("proxy rejected update")
	rulesErr := errors.New("installing proxy rules failed")
	tests := []struct {
		name       string
		cancel     bool
		reject     bool
		noWait     bool
		noPolicy   bool
		accepted   uint64
		rulesError error
		err        error
	}{
		{name: "ack"},
		{name: "nack", reject: true, err: nackErr},
		{name: "parent-canceled", cancel: true, reject: true, err: context.Canceled},
		{name: "rules-error", rulesError: rulesErr, err: rulesErr},
		{name: "no-wait", noWait: true},
		{name: "no-policy", noPolicy: true},
		{name: "newer-policy-already-accepted", accepted: 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &recordingAckRedirectProxy{err: tt.rulesError}
			ep := &Endpoint{
				proxy:               proxy,
				IPv4:                netip.MustParseAddr("10.0.0.1"),
				isIngress:           true,
				status:              NewEndpointStatus(),
				proxyPolicyRevision: tt.accepted,
			}
			ep.logger.Store(hivetest.Logger(t))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wg := completion.NewWaitGroup(ctx)
			defer wg.Cancel()
			var submittedRevision uint64
			if !tt.noPolicy {
				submitted := selectorPolicy.DistillPolicy(ep.getLogger(), ep, nil)
				ep.desiredPolicy = submitted
				t.Cleanup(func() {
					submitted.Ready()
					submitted.Detach(ep.getLogger())
				})
				err, rollback, revision := ep.ApplyPolicyMapChanges(wg)
				require.NoError(t, err)
				if rollback != nil {
					rollback.Finalize()
				}
				submittedRevision = revision
				require.Equal(t, submitted.SelectorPolicy.L4Policy.Revision, revision)
				require.NotZero(t, revision)

				// A newer desired policy must not be reported as accepted by
				// the wait for the previously submitted policy.
				ep.desiredPolicy = policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
				ep.desiredPolicy.SelectorPolicy.L4Policy.Revision = revision + 1
				ep.desiredPolicyRevision = revision + 2
			}
			var callbackErr error
			pending := wg.AddCompletionWithCallback(nil, func(err error) { callbackErr = err })
			result := wg.AddCompletionWithCallback(nil, nil)
			if tt.reject {
				result.Complete(nackErr)
			} else {
				pending.Complete(nil)
				result.Complete(nil)
			}
			if tt.cancel {
				cancel()
			}

			redirects := map[string]uint16{"redirect": 12345}
			waitGroup := wg
			if tt.noWait {
				waitGroup = nil
			}
			require.ErrorIs(t, ep.waitForProxyCompletions(ctx, waitGroup, redirects, submittedRevision), tt.err)
			expectedRevision := tt.accepted
			if !tt.reject && !tt.noWait {
				expectedRevision = max(expectedRevision, submittedRevision)
			}
			require.Equal(t, expectedRevision, ep.proxyPolicyRevision)
			if tt.cancel {
				// Regeneration drains an early return before reverting resources.
				wg.Cancel()
			}
			if tt.reject {
				require.ErrorIs(t, callbackErr, context.Canceled)
				require.Nil(t, proxy.redirects, "a failed wait must not acknowledge proxy ports")
			} else if !tt.noWait {
				require.NoError(t, callbackErr)
				require.Equal(t, redirects, proxy.redirects)
			}
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
