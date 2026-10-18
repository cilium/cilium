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
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	fakepolicymap "github.com/cilium/cilium/pkg/maps/policymap/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
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
	var pending *completion.Completion
	// Queue asynchronous work before pre-compilation fails.
	ep.dnsRulesAPI = noopDNSRulesAPI{onRead: func() {
		pending = datapath.proxyWaitGroup.AddCompletion(nil)
	}}
	var reverted bool
	datapath.revertibles.AddRevert(func() error {
		require.ErrorIs(t, pending.Err(), context.Canceled, "pending completions must settle before rollback")
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

type recordingAckRedirectProxy struct {
	FakeEndpointProxy
	redirects map[string]uint16
	err       error
	onAck     func()
}

func (p *recordingAckRedirectProxy) AckRedirects(_ context.Context, redirects map[string]uint16) error {
	p.redirects = redirects
	if p.onAck != nil {
		p.onAck()
	}
	return p.err
}

func TestWaitForProxyCompletionsDrainsRejectedUpdates(t *testing.T) {
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
			pending := wg.AddCompletion(nil)
			result := wg.AddCompletion(nil)
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
				require.ErrorIs(t, pending.Err(), context.Canceled)
				require.Nil(t, proxy.redirects, "a failed wait must not acknowledge proxy ports")
			} else if !tt.noWait {
				require.NoError(t, pending.Err())
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

type publicationOrchestrator struct {
	fakeendpoint.FakeOrchestrator
	events *[]string
}

func (o *publicationOrchestrator) ReloadDatapath(_ context.Context, _ endpointtypes.Endpoint, _ *metrics.SpanStat, beforeExpose func() error) (string, error) {
	*o.events = append(*o.events, "load")
	if err := beforeExpose(); err != nil {
		return "", err
	}
	*o.events = append(*o.events, "programs")
	return "", nil
}

type publicationEndpointMap struct {
	lxcmap.Map
	events *[]string
}

func (m *publicationEndpointMap) WriteEndpoint(lxcmap.EndpointFrontend) error {
	*m.events = append(*m.events, "metadata")
	return nil
}

type noopPolicyMapPressureUpdater struct{}

func (*noopPolicyMapPressureUpdater) Update(PolicyMapPressureEvent) {}
func (*noopPolicyMapPressureUpdater) Remove(uint16)                 {}

func TestRegenerateBPFWaitsBeforePublication(t *testing.T) {
	f := newPolicyTestFixture(t)
	nackErr := errors.New("proxy rejected update")
	rulesErr := errors.New("installing proxy rules failed")
	for _, tc := range []struct {
		name        string
		populated   bool
		noReload    bool
		noPolicyMap bool
		cancel      bool
		proxyErr    error
		rulesErr    error
		wantErr     error
		events      []string
	}{
		{name: "empty map", events: []string{"load", "done", "rules", "programs", "metadata"}},
		{name: "populated map", populated: true, events: []string{"load", "done", "rules", "programs", "metadata"}},
		{name: "no reload", populated: true, noReload: true, events: []string{"done", "rules", "metadata"}},
		{name: "no policy map", noReload: true, noPolicyMap: true, events: []string{"done", "rules", "metadata"}},
		{name: "NACK", proxyErr: nackErr, wantErr: nackErr, events: []string{"load", "done"}},
		{name: "canceled", cancel: true, wantErr: context.Canceled, events: []string{"load", "done"}},
		{name: "rules error", rulesErr: rulesErr, wantErr: rulesErr, events: []string{"load", "done", "rules"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			desired := policy.NewEndpointPolicy(logger, f.repo)
			key := types.KeyForDirection(trafficdirection.Egress).WithIdentity(identity.ReservedIdentityWorld).WithPortProto(u8proto.TCP, 80)
			entry := types.MapStateEntry{ProxyPort: 15000}
			desired.CopyMapStateFrom(policy.MapStateMap{key: entry})
			desired.Redirects = map[string]uint16{"redirect": 15000}

			ep := newRegenTestEndpoint(t, f.repo, desired)
			ep.realizedPolicy = policy.NewEndpointPolicy(logger, f.repo)
			ep.Options = option.NewIntOptions(&EndpointMutableOptionLibrary)
			ep.status = NewEndpointStatus()
			ep.PolicyMapPressureUpdater = &noopPolicyMapPressureUpdater{}
			aliveCtx, closeEndpoint := context.WithCancel(t.Context())
			ep.aliveCtx = aliveCtx
			t.Cleanup(func() {
				ep.dnsRulesAPI = noopDNSRulesAPI{}
				closeEndpoint()
				if trigger := ep.dnsHistoryTrigger.Load(); trigger != nil {
					trigger.Shutdown()
				}
			})

			pm := fakepolicymap.NewFakePolicyMap()
			ep.policyMap = pm
			if tc.populated {
				k := policymap.NewKeyFromPolicyKey(key)
				v := policymap.NewEntryFromPolicyEntry(k, types.MapStateEntry{})
				require.NoError(t, pm.Update(&k, &v))
			}
			if tc.noPolicyMap {
				ep.policyMap = nil
				ep.properties = map[string]any{
					endpointtypes.PropertySkipBPFPolicy: true,
					endpointtypes.PropertyAtHostNS:      true,
				}
			}
			var events []string
			ep.orchestrator = &publicationOrchestrator{events: &events}
			ep.lxcMap = &publicationEndpointMap{events: &events}
			ep.proxy = &recordingAckRedirectProxy{err: tc.rulesErr, onAck: func() {
				events = append(events, "rules")
			}}
			datapath := &datapathRegenerationContext{
				currentDir:        t.TempDir(),
				nextDir:           t.TempDir(),
				ctCleaned:         make(chan struct{}),
				regenerationLevel: regeneration.RegenerateWithDatapath,
				policyResult: &policyGenerateResult{
					endpointPolicy: desired,
					identity:       ep.getIdentity(),
					policyRevision: f.repo.GetRevision(),
				},
			}
			if tc.noReload {
				datapath.regenerationLevel = regeneration.RegenerateWithoutDatapath
			}
			var pending *completion.Completion
			ep.dnsRulesAPI = noopDNSRulesAPI{onRead: func() {
				pending = datapath.proxyWaitGroup.AddCompletion(nil)
			}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			regenCtx := &regenerationContext{
				parentContext:               ctx,
				datapathRegenerationContext: datapath,
				DoneFunc: func() {
					events = append(events, "done")
					// Empty maps must be filled before loading to avoid blackholes;
					// populated maps must retain their old policy until the wait.
					if !tc.noPolicyMap {
						dump, err := pm.DumpToMapStateMap()
						require.NoError(t, err)
						require.Equal(t, !tc.populated, dump[key].ProxyPort == entry.ProxyPort)
					}
					if tc.cancel {
						cancel()
					}
					pending.Complete(tc.proxyErr)
				},
			}

			ep.buildMutex.Lock()
			_, err := ep.regenerateBPF(regenCtx)
			ep.buildMutex.Unlock()
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				regenErr, ok := errors.AsType[*regenerationError](err)
				require.True(t, ok)
				require.Equal(t, regenerationFailureReasonProxyPolicyError, regenErr.GetReason())
			} else {
				require.NoError(t, err)
				if !tc.noPolicyMap {
					dump, err := pm.DumpToMapStateMap()
					require.NoError(t, err)
					require.Equal(t, entry.ProxyPort, dump[key].ProxyPort)
				}
			}
			require.Equal(t, tc.events, events)
		})
	}
}
