// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	proxyendpoint "github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

type policyCompletionOwner string

func (o policyCompletionOwner) ID() string {
	return string(o)
}

func (policyCompletionOwner) CleanupAfterWait(*completion.Completion) {}

type recordingEndpointProxy struct {
	mu lock.Mutex

	syncErrByEndpoint map[uint64]error
	completions       map[uint64]*completion.Completion
	revertCalls       map[uint64]int
	finalizeCalls     map[uint64]int

	updatesSeen     int
	expectedUpdates int
	updatesObserved chan struct{}
}

func newRecordingEndpointProxy() *recordingEndpointProxy {
	return &recordingEndpointProxy{
		syncErrByEndpoint: make(map[uint64]error),
		completions:       make(map[uint64]*completion.Completion),
		revertCalls:       make(map[uint64]int),
		finalizeCalls:     make(map[uint64]int),
	}
}

func (p *recordingEndpointProxy) expectUpdates(expected int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.completions = make(map[uint64]*completion.Completion)
	p.revertCalls = make(map[uint64]int)
	p.finalizeCalls = make(map[uint64]int)
	p.updatesSeen = 0
	p.expectedUpdates = expected
	p.updatesObserved = make(chan struct{})
}

func (p *recordingEndpointProxy) setSynchronousError(endpointID uint64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		delete(p.syncErrByEndpoint, endpointID)
		return
	}
	p.syncErrByEndpoint[endpointID] = err
}

func (p *recordingEndpointProxy) waitForUpdates(t *testing.T) {
	t.Helper()

	p.mu.Lock()
	ch := p.updatesObserved
	p.mu.Unlock()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxy update calls")
	}
}

func (p *recordingEndpointProxy) completeUpdate(t *testing.T, endpointID uint64, err error) {
	t.Helper()

	p.mu.Lock()
	comp := p.completions[endpointID]
	p.mu.Unlock()

	require.NotNilf(t, comp, "missing completion for endpoint %d", endpointID)
	comp.Complete(err)
}

func (p *recordingEndpointProxy) revertCount(endpointID uint64) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revertCalls[endpointID]
}

func (p *recordingEndpointProxy) finalizeCount(endpointID uint64) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.finalizeCalls[endpointID]
}

func (p *recordingEndpointProxy) totalCallbackCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	total := 0
	for _, count := range p.revertCalls {
		total += count
	}
	for _, count := range p.finalizeCalls {
		total += count
	}
	return total
}

func (p *recordingEndpointProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, epID uint16, wg *completion.WaitGroup) (proxyPort uint16, err error, revertFunc revert.RevertFunc) {
	return 0, nil, nil
}

func (p *recordingEndpointProxy) RemoveRedirect(id string) {}

func (p *recordingEndpointProxy) UpdateNetworkPolicy(ep proxyendpoint.EndpointUpdater, epp *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.RevertFunc, revert.FinalizeFunc) {
	endpointID := ep.GetID()

	p.mu.Lock()
	err := p.syncErrByEndpoint[endpointID]
	trackUpdates := p.expectedUpdates > 0
	if err == nil && wg != nil && trackUpdates {
		p.completions[endpointID] = wg.AddCompletionWithCallback(policyCompletionOwner("network-policy-update"), nil)
	}
	if trackUpdates {
		p.updatesSeen++
	}
	if trackUpdates && p.updatesSeen == p.expectedUpdates && p.updatesObserved != nil {
		close(p.updatesObserved)
	}
	p.mu.Unlock()

	if err != nil {
		return err, nil, nil
	}

	return nil, func() error {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.revertCalls[endpointID]++
			return nil
		}, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.finalizeCalls[endpointID]++
		}
}

func (p *recordingEndpointProxy) RemoveNetworkPolicy(ep proxyendpoint.EndpointInfoSource) {}

func (p *recordingEndpointProxy) UpdateSDP(rules map[identity.NumericIdentity]policy.SelectorPolicy) {
}

func (p *recordingEndpointProxy) GetListenerProxyPort(listener string) uint16 {
	return 0
}

func (p *recordingEndpointProxy) IsSDPEnabled() bool {
	return false
}

func newUpdatePolicyMapsTestRepo(t *testing.T) (*policy.Repository, identitymanager.IDManager) {
	t.Helper()

	logger := hivetest.Logger(t)
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(
		logger,
		nil,
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idmgr,
		testpolicy.NewPolicyMetricsNoop(),
	)

	oldPolicyMode := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)
	t.Cleanup(func() {
		policy.SetPolicyEnabled(oldPolicyMode)
	})

	repo.MustAddList(api.Rules{{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{
					Port:     "80",
					Protocol: api.ProtoTCP,
				}},
				Rules: &api.L7Rules{
					HTTP: []api.PortRuleHTTP{{
						Path:   "/",
						Method: "GET",
					}},
				},
			}},
		}},
	}})

	return repo, idmgr
}

func newUpdatePolicyMapsTestEndpoint(t *testing.T, mgr *endpointManager, repo policy.PolicyRepository, idmgr identitymanager.IDManager, proxy endpoint.EndpointProxy, modelID int, addr netip.Addr) *endpoint.Endpoint {
	t.Helper()

	model := newTestEndpointModel(modelID, endpoint.StateWaitingForIdentity)
	ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
		Logger:           hivetest.Logger(t),
		EPBuildQueue:     &endpoint.MockEndpointBuildQueue{},
		Orchestrator:     &fakeendpoint.FakeOrchestrator{},
		PolicyRepo:       repo,
		IdentityManager:  idmgr,
		NamedPortsGetter: testipcache.NewMockIPCache(),
		IPSecConfig:      fakeipsec.Config{},
		WgConfig:         &fakewireguard.Config{},
		CTMapGC:          ctmap.NewFakeGCRunner(),
		Allocator:        testidentity.NewMockIdentityAllocator(nil),
		KVStoreSynchronizer: ipcache.NewIPIdentitySynchronizer(
			hivetest.Logger(t),
			kvstore.SetupDummy(t, kvstore.DisabledBackendName),
		),
	}, nil, proxy, model, nil)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

	ep.IPv4 = addr
	ep.SetIdentity(identity.NewIdentityFromLabelArray(identity.NumericIdentity(1000+modelID), labels.ParseLabelArray("k8s:bar")))

	err = mgr.expose(ep)
	require.NoError(t, err)

	success := <-ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            regeneration.ReasonPolicyUpdate,
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
	})
	require.True(t, success)

	return ep
}

func TestUpdatePolicyMapsFinalizesDeferredNetworkPolicyCallbacksAfterSuccessfulWait(t *testing.T) {
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	repo, idmgr := newUpdatePolicyMapsTestRepo(t)
	proxy := newRecordingEndpointProxy()

	ep1 := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 101, netip.MustParseAddr("10.0.0.1"))
	ep2 := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 102, netip.MustParseAddr("10.0.0.2"))

	proxy.expectUpdates(2)

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		errCh <- mgr.UpdatePolicyMaps(ctx)
	}()

	proxy.waitForUpdates(t)
	require.Zero(t, proxy.totalCallbackCount())

	proxy.completeUpdate(t, ep1.GetID(), nil)
	proxy.completeUpdate(t, ep2.GetID(), nil)

	require.NoError(t, <-errCh)
	require.Equal(t, 0, proxy.revertCount(ep1.GetID()))
	require.Equal(t, 0, proxy.revertCount(ep2.GetID()))
	require.Equal(t, 1, proxy.finalizeCount(ep1.GetID()))
	require.Equal(t, 1, proxy.finalizeCount(ep2.GetID()))
}

func TestUpdatePolicyMapsRevertsDeferredNetworkPolicyCallbacksAfterProxyWaitFailure(t *testing.T) {
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	repo, idmgr := newUpdatePolicyMapsTestRepo(t)
	proxy := newRecordingEndpointProxy()

	ep1 := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 201, netip.MustParseAddr("10.0.1.1"))
	ep2 := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 202, netip.MustParseAddr("10.0.1.2"))

	proxy.expectUpdates(2)

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		errCh <- mgr.UpdatePolicyMaps(ctx)
	}()

	proxy.waitForUpdates(t)
	require.Zero(t, proxy.totalCallbackCount())

	proxy.completeUpdate(t, ep1.GetID(), errors.New("proxy wait failed"))

	err := <-errCh
	require.Error(t, err)
	require.ErrorContains(t, err, "proxy updates failed")
	require.Equal(t, 1, proxy.revertCount(ep1.GetID()))
	require.Equal(t, 1, proxy.revertCount(ep2.GetID()))
	require.Equal(t, 0, proxy.finalizeCount(ep1.GetID()))
	require.Equal(t, 0, proxy.finalizeCount(ep2.GetID()))
}

func TestUpdatePolicyMapsDoesNotDeferCallbacksForSynchronousApplyFailure(t *testing.T) {
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	repo, idmgr := newUpdatePolicyMapsTestRepo(t)
	proxy := newRecordingEndpointProxy()

	ep1 := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 301, netip.MustParseAddr("10.0.2.1"))
	ep2 := newUpdatePolicyMapsTestEndpoint(t, mgr, repo, idmgr, proxy, 302, netip.MustParseAddr("10.0.2.2"))

	proxy.expectUpdates(2)
	proxy.setSynchronousError(ep1.GetID(), errors.New("sync proxy error"))

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		errCh <- mgr.UpdatePolicyMaps(ctx)
	}()

	proxy.waitForUpdates(t)
	require.Zero(t, proxy.totalCallbackCount())

	proxy.completeUpdate(t, ep2.GetID(), nil)

	require.NoError(t, <-errCh)
	require.Equal(t, 0, proxy.revertCount(ep1.GetID()))
	require.Equal(t, 0, proxy.finalizeCount(ep1.GetID()))
	require.Equal(t, 0, proxy.revertCount(ep2.GetID()))
	require.Equal(t, 1, proxy.finalizeCount(ep2.GetID()))
}
