// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_stream "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	envoyconfig "github.com/cilium/cilium/pkg/envoy/config"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/policy/compute"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	proxyendpoint "github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	testcertificatemanager "github.com/cilium/cilium/pkg/testutils/certificatemanager"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testmonitor "github.com/cilium/cilium/pkg/testutils/monitor"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

const (
	benchmarkEndpointCount     = 184
	benchmarkMaxIdentityCount  = 1_530
	benchmarkIdentityBatchSize = 1
	benchmarkFirstRemoteID     = identity.NumericIdentity(10_000)
	benchmarkProxyPort         = 10_000
	benchmarkEnvoyProcessTime  = time.Second
)

type benchmarkPolicyWorkload struct {
	name              string
	identityLabels    labels.LabelArray
	expectPolicyChurn bool
}

type benchmarkEnvoy interface {
	reset()
	report(*testing.B)
	err() error
	close()
}

type benchmarkEnvoyState struct {
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	responses atomic.Uint64

	errMu  sync.Mutex
	runErr error
}

func newBenchmarkEnvoyState(ctx context.Context) benchmarkEnvoyState {
	ctx, cancel := context.WithCancel(ctx)
	return benchmarkEnvoyState{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

func (e *benchmarkEnvoyState) reset() {
	e.responses.Store(0)
}

func (e *benchmarkEnvoyState) report(b *testing.B) {
	b.ReportMetric(float64(e.responses.Load())/float64(b.N), "xds-responses")
}

func (e *benchmarkEnvoyState) fail(err error) {
	e.errMu.Lock()
	if e.runErr == nil {
		e.runErr = err
	}
	e.errMu.Unlock()
}

func (e *benchmarkEnvoyState) err() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	return e.runErr
}

func (e *benchmarkEnvoyState) processResponse() bool {
	e.responses.Add(1)
	timer := time.NewTimer(benchmarkEnvoyProcessTime)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-e.ctx.Done():
		return false
	}
}

// benchmarkSnapshotCache counts calls made by the production ADS server. All
// cache work is delegated unchanged to the real xdsnew.Cache.
type benchmarkSnapshotCache struct {
	xdsnew.Cache

	generated atomic.Uint64
	published atomic.Uint64
	versioned atomic.Uint64
}

func (c *benchmarkSnapshotCache) reset() {
	c.generated.Store(0)
	c.published.Store(0)
	c.versioned.Store(0)
}

func (c *benchmarkSnapshotCache) report(b *testing.B) {
	b.ReportMetric(float64(c.published.Load())/float64(b.N), "cache-updates")
	b.ReportMetric(float64(c.generated.Load())/float64(b.N), "snapshots")
	b.ReportMetric(float64(c.versioned.Load())/float64(b.N), "versions")
}

func (c *benchmarkSnapshotCache) GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	c.generated.Add(1)
	return c.Cache.GenerateSnapshot(resources, logger)
}

func (c *benchmarkSnapshotCache) UpdateSnapshot(ctx context.Context, nodeID string, snapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLs map[string]func(error), revert func()) error {
	c.published.Add(1)
	return c.Cache.UpdateSnapshot(ctx, nodeID, snapshot, wg, updatedTypeURLs, revert)
}

func (c *benchmarkSnapshotCache) AwaitCurrentVersion(nodeID string, wg *completion.WaitGroup, typeURLs map[string]func(error)) error {
	err := c.Cache.AwaitCurrentVersion(nodeID, wg, typeURLs)
	if err == nil && wg != nil {
		// The benchmark has no Envoy process. Simulate the ACK that would
		// complete waiters attached to the already-published version.
		for typeURL := range typeURLs {
			c.Cache.GetCompletionCallbacks().CompleteUnsentPendingCompletions(nodeID, typeURL, nil)
		}
	}
	return err
}

func (c *benchmarkSnapshotCache) GetVersion(resources *xds.Resources) string {
	c.versioned.Add(1)
	return c.Cache.GetVersion(resources)
}

// benchmarkADSEnvoy keeps a real go-control-plane SotW watch open for NPDS.
// It observes responses through the production completion callbacks, waits as
// Envoy would while applying them, then ACKs and opens the next watch.
type benchmarkADSEnvoy struct {
	benchmarkEnvoyState

	cache        xdsnew.Cache
	subscription envoy_stream.Subscription
	responses    chan cache.Response
	streamID     int64

	watchMu     sync.Mutex
	cancelWatch func()
}

func newBenchmarkADSEnvoy(b *testing.B, xdsCache xdsnew.Cache) *benchmarkADSEnvoy {
	b.Helper()

	envoy := &benchmarkADSEnvoy{
		benchmarkEnvoyState: newBenchmarkEnvoyState(b.Context()),
		cache:               xdsCache,
		subscription:        envoy_stream.NewSotwSubscription(nil, true),
		responses:           make(chan cache.Response, 1),
		streamID:            1,
	}

	// Establish and ACK the initial NPDS state without charging fixture setup
	// to the simulated response processing time. Leave the next watch open so
	// the first timed resource update sees the same state as an idle Envoy.
	require.NoError(b, envoy.openWatch(""))
	var initial cache.Response
	select {
	case initial = <-envoy.responses:
	case <-envoy.ctx.Done():
		b.Fatal("timed out waiting for initial ADS benchmark response")
	}
	initialVersion := envoy.observeResponse(initial)
	require.NoError(b, envoy.openWatch(initialVersion))

	go envoy.run()
	b.Cleanup(envoy.close)
	return envoy
}

func (e *benchmarkADSEnvoy) setCancelWatch(cancel func()) {
	e.watchMu.Lock()
	previous := e.cancelWatch
	if e.ctx.Err() == nil {
		e.cancelWatch = cancel
	} else {
		e.cancelWatch = nil
	}
	e.watchMu.Unlock()
	if previous != nil {
		previous()
	}
	if e.ctx.Err() != nil && cancel != nil {
		cancel()
	}
}

func (e *benchmarkADSEnvoy) openWatch(ackedVersion string) error {
	request := &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core.Node{Id: localNodeID},
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: ackedVersion,
	}
	if err := e.cache.GetCompletionCallbacks().OnStreamRequest(e.streamID, request); err != nil {
		return err
	}
	cancel, err := e.cache.CreateWatch(request, &e.subscription, e.responses)
	if err != nil {
		return err
	}
	e.setCancelWatch(cancel)
	return nil
}

func (e *benchmarkADSEnvoy) observeResponse(response cache.Response) string {
	version := response.GetResponseVersion()
	e.subscription.SetReturnedResources(response.GetReturnedResources())
	e.cache.GetCompletionCallbacks().OnStreamResponse(
		response.GetContext(),
		e.streamID,
		response.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     NetworkPolicyTypeURL,
		},
	)
	return version
}

func (e *benchmarkADSEnvoy) run() {
	defer close(e.done)
	for {
		select {
		case <-e.ctx.Done():
			return
		case response := <-e.responses:
			version := e.observeResponse(response)
			if !e.processResponse() {
				return
			}
			if err := e.openWatch(version); err != nil {
				e.fail(err)
				e.cache.GetCompletionCallbacks().CancelPendingCompletions(NetworkPolicyTypeURL)
				return
			}
		}
	}
}

func (e *benchmarkADSEnvoy) close() {
	e.cancel()
	e.watchMu.Lock()
	cancelWatch := e.cancelWatch
	e.cancelWatch = nil
	e.watchMu.Unlock()
	if cancelWatch != nil {
		cancelWatch()
	}
	<-e.done
}

// benchmarkLegacyEnvoy follows the legacy cache's version notification stream.
// Updates that arrive while a response is being processed are naturally folded
// into the next response, matching the legacy SotW and Delta server behavior.
type benchmarkLegacyEnvoy struct {
	benchmarkEnvoyState

	cache       *xds.Cache
	ackObserver xds.ResourceVersionAckObserver
	lastVersion uint64
}

func newBenchmarkLegacyEnvoy(b *testing.B, xdsCache *xds.Cache, ackObserver xds.ResourceVersionAckObserver) *benchmarkLegacyEnvoy {
	b.Helper()

	envoy := &benchmarkLegacyEnvoy{
		benchmarkEnvoyState: newBenchmarkEnvoyState(b.Context()),
		cache:               xdsCache,
		ackObserver:         ackObserver,
	}
	initial := xdsCache.GetResources(NetworkPolicyTypeURL, 0, nil)
	require.NotNil(b, initial)
	envoy.ack(initial)
	envoy.lastVersion = initial.Version

	go envoy.run()
	b.Cleanup(envoy.close)
	return envoy
}

func (e *benchmarkLegacyEnvoy) ack(response *xds.VersionedResources) {
	resourceNames := make([]string, 0, len(response.VersionedResources))
	for _, resource := range response.VersionedResources {
		resourceNames = append(resourceNames, resource.Name)
	}
	e.ackObserver.HandleResourceVersionAck(
		"127.0.0.1",
		response.Version,
		response.Version,
		false,
		"",
		NetworkPolicyTypeURL,
		resourceNames,
	)
}

func (e *benchmarkLegacyEnvoy) run() {
	defer close(e.done)
	for {
		currentVersion, changed := e.cache.VersionState()
		if currentVersion <= e.lastVersion {
			select {
			case <-e.ctx.Done():
				return
			case <-changed:
			}
			continue
		}

		response := e.cache.GetResources(NetworkPolicyTypeURL, e.lastVersion, nil)
		if response == nil {
			e.lastVersion = currentVersion
			continue
		}
		if !e.processResponse() {
			return
		}
		e.ack(response)
		e.lastVersion = response.Version
	}
}

func (e *benchmarkLegacyEnvoy) close() {
	e.cancel()
	<-e.done
}

type benchmarkLegacyCacheStats struct {
	cache        *xds.Cache
	startVersion uint64
}

func (s *benchmarkLegacyCacheStats) reset() {
	s.startVersion, _ = s.cache.VersionState()
}

func (s *benchmarkLegacyCacheStats) report(b *testing.B) {
	version, _ := s.cache.VersionState()
	b.ReportMetric(float64(version-s.startVersion)/float64(b.N), "cache-updates")
	b.ReportMetric(0, "snapshots")
	b.ReportMetric(0, "versions")
}

type benchmarkXDSStats interface {
	reset()
	report(*testing.B)
}

type benchmarkNoopXDSMetrics struct{}

func (benchmarkNoopXDSMetrics) IncreaseNACK(string)   {}
func (benchmarkNoopXDSMetrics) IncreaseACK(string)    {}
func (benchmarkNoopXDSMetrics) IncreaseCancel(string) {}

// benchmarkObservedXDSServer counts calls at the production server boundary;
// the selected server still performs all cilium.NetworkPolicy construction.
type benchmarkObservedXDSServer struct {
	xds.XDSServer

	networkPolicies          atomic.Uint64
	networkPoliciesCompleted atomic.Uint64
	networkPolicyCompleted   chan struct{}
}

func (s *benchmarkObservedXDSServer) UpdateNetworkPolicy(ctx context.Context, ep proxyendpoint.EndpointUpdater, epp *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.RevertFunc, revert.FinalizeFunc) {
	s.networkPolicies.Add(1)
	err, revertFunc, finalizeFunc := s.XDSServer.UpdateNetworkPolicy(ctx, ep, epp, wg)
	s.networkPoliciesCompleted.Add(1)
	select {
	case s.networkPolicyCompleted <- struct{}{}:
	default:
	}
	return err, revertFunc, finalizeFunc
}

func (s *benchmarkObservedXDSServer) reset() {
	s.networkPolicies.Store(0)
	s.networkPoliciesCompleted.Store(0)
	select {
	case <-s.networkPolicyCompleted:
	default:
	}
}

func (s *benchmarkObservedXDSServer) report(b *testing.B) {
	b.ReportMetric(float64(s.networkPolicies.Load())/float64(b.N), "policies")
}

func (s *benchmarkObservedXDSServer) completedNetworkPolicies() uint64 {
	return s.networkPoliciesCompleted.Load()
}

func (s *benchmarkObservedXDSServer) waitForNetworkPolicies(ctx context.Context, target uint64) error {
	for s.networkPoliciesCompleted.Load() < target {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.networkPolicyCompleted:
		}
	}
	return nil
}

type benchmarkXDSBackend struct {
	server          xds.XDSServer
	serverStats     *benchmarkObservedXDSServer
	stats           benchmarkXDSStats
	networkPolicies func() []*cilium.NetworkPolicy
	startEnvoy      func(*testing.B) benchmarkEnvoy
}

func newBenchmarkXDSBackend(b *testing.B, logger *slog.Logger, mode envoyconfig.XDSMode) benchmarkXDSBackend {
	b.Helper()

	secretManager := certificatemanager.NewMockSecretManagerInline()
	serverConfig := xdsServerConfig{
		envoyXDSMode: mode,
		metrics:      benchmarkNoopXDSMetrics{},
	}
	localEndpointStore := newLocalEndpointStore()
	translator := envoypolicy.NewEnvoyL7RulesTranslator(logger, secretManager)

	var backend benchmarkXDSBackend
	if mode.IsADS() {
		observedCache := &benchmarkSnapshotCache{Cache: xdsnew.NewCache(logger, mode.IsStrictADS())}
		server := newADSServerWithCache(observedCache, logger, nil, localEndpointStore, serverConfig, secretManager, nil)
		server.l7RulesTranslator = translator
		backend = benchmarkXDSBackend{
			server: server,
			stats:  observedCache,
			networkPolicies: func() []*cilium.NetworkPolicy {
				resources := observedCache.GetAllResources(localNodeID)
				policies := make([]*cilium.NetworkPolicy, 0, len(resources.NetworkPolicies))
				for _, networkPolicy := range resources.NetworkPolicies {
					policies = append(policies, networkPolicy)
				}
				return policies
			},
			startEnvoy: func(b *testing.B) benchmarkEnvoy {
				return newBenchmarkADSEnvoy(b, observedCache)
			},
		}
	} else {
		server := newXDSServer(logger, nil, nil, localEndpointStore, serverConfig, secretManager)
		server.l7RulesTranslator = translator
		ackObserver, ok := server.networkPolicyMutator.(xds.ResourceVersionAckObserver)
		require.True(b, ok)
		backend = benchmarkXDSBackend{
			server: server,
			stats:  &benchmarkLegacyCacheStats{cache: server.networkPolicyCache},
			networkPolicies: func() []*cilium.NetworkPolicy {
				resources := server.networkPolicyCache.GetResources(NetworkPolicyTypeURL, 0, nil)
				if resources == nil {
					return nil
				}
				policies := make([]*cilium.NetworkPolicy, 0, len(resources.VersionedResources))
				for _, resource := range resources.VersionedResources {
					networkPolicy, ok := resource.Resource.(*cilium.NetworkPolicy)
					require.True(b, ok)
					policies = append(policies, networkPolicy)
				}
				return policies
			},
			startEnvoy: func(b *testing.B) benchmarkEnvoy {
				return newBenchmarkLegacyEnvoy(b, server.networkPolicyCache, ackObserver)
			},
		}
	}

	require.NoError(b, backend.server.AddListener(
		b.Context(), "benchmark-l7-listener", policy.ParserTypeHTTP, benchmarkProxyPort,
		false, false, nil, nil,
	))
	backend.serverStats = &benchmarkObservedXDSServer{
		XDSServer:              backend.server,
		networkPolicyCompleted: make(chan struct{}, 1),
	}
	backend.server = backend.serverStats
	return backend
}

type benchmarkEndpointSynchronizer struct{}

func (*benchmarkEndpointSynchronizer) RunK8sCiliumEndpointSync(*endpoint.Endpoint, cell.Health) {}
func (*benchmarkEndpointSynchronizer) DeleteK8sCiliumEndpointSync(*endpoint.Endpoint)           {}

// benchmarkEndpointProxy supplies the redirect-management half of
// endpoint.EndpointProxy, which is not owned by the xDS server. Network policy
// updates and removals are promoted methods of the selected production server.
type benchmarkEndpointProxy struct {
	xds.XDSServer
}

func (*benchmarkEndpointProxy) CreateOrUpdateRedirect(context.Context, policy.ProxyPolicy, string, uint16, *completion.WaitGroup) (uint16, error, revert.RevertFunc) {
	// A non-zero port makes the redirect realized, as it would be in production.
	// Incremental L7 selector changes are otherwise skipped before the xDS path.
	return benchmarkProxyPort, nil, nil
}

func (*benchmarkEndpointProxy) RemoveRedirect(string) {}

func (*benchmarkEndpointProxy) UpdateSDP(map[identity.NumericIdentity]policy.SelectorPolicy) {}

func (*benchmarkEndpointProxy) GetListenerProxyPort(string) uint16 { return benchmarkProxyPort }

func (*benchmarkEndpointProxy) IsSDPEnabled() bool { return false }

var _ endpoint.EndpointProxy = (*benchmarkEndpointProxy)(nil)

// Keep the promoted production method's interface visible at compile time.
var _ interface {
	UpdateNetworkPolicy(context.Context, proxyendpoint.EndpointUpdater, *policy.EndpointPolicy, *completion.WaitGroup) (error, revert.RevertFunc, revert.FinalizeFunc)
} = (*benchmarkEndpointProxy)(nil)

type identityUpdateBenchmark struct {
	cacheStats      benchmarkXDSStats
	serverStats     *benchmarkObservedXDSServer
	envoy           benchmarkEnvoy
	updater         policycell.IdentityUpdater
	networkPolicies func() []*cilium.NetworkPolicy
}

func newIdentityUpdateBenchmark(b *testing.B, mode envoyconfig.XDSMode) *identityUpdateBenchmark {
	b.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldDefaultLogger := logging.DefaultSlogLogger
	logging.DefaultSlogLogger = logger
	b.Cleanup(func() { logging.DefaultSlogLogger = oldDefaultLogger })

	manager := endpointmanager.New(logger, nil, &benchmarkEndpointSynchronizer{}, nil, nil, &testmonitor.TestMonitorAgent{}, endpointmanager.EndpointManagerConfig{
		EndpointPolicyUpdateTimeout:          5 * time.Minute,
		BPFPolicyMapPressureMetricsThreshold: 0.1,
	})

	var (
		repo     policy.PolicyRepository
		idmgr    identitymanager.IDManager
		computer compute.PolicyRecomputer
		updater  policycell.IdentityUpdater
	)

	h := hive.New(
		metrics.NewCell("ads-bench"),
		cell.ProvidePrivate(func() *option.DaemonConfig { return option.Config }),
		cell.ProvidePrivate(func() cmtypes.ClusterInfo { return cmtypes.DefaultClusterInfo }),
		cell.ProvidePrivate(func() certificatemanager.CertificateManager {
			return &testcertificatemanager.Fake{}
		}),
		cell.ProvidePrivate(func() envoypolicy.EnvoyL7RulesTranslator {
			return envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline())
		}),
		cell.ProvidePrivate(func() policytypes.PolicyMetrics { return testpolicy.NewPolicyMetricsNoop() }),
		cell.ProvidePrivate(func() endpointmanager.EndpointManager { return manager }),
		identitymanager.Cell,
		compute.Cell,
		policycell.Cell,
		cell.Invoke(func(r policy.PolicyRepository, ids identitymanager.IDManager, c compute.PolicyRecomputer, u policycell.IdentityUpdater) {
			repo = r
			idmgr = ids
			computer = c
			updater = u
		}),
	)
	require.NoError(b, h.Start(logger, b.Context()))
	b.Cleanup(func() {
		require.NoError(b, h.Stop(logger, context.Background()))
	})

	backend := newBenchmarkXDSBackend(b, logger, mode)
	endpointProxy := &benchmarkEndpointProxy{XDSServer: backend.server}

	oldPolicyMode := policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)
	b.Cleanup(func() { policy.SetPolicyEnabled(oldPolicyMode) })

	rule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("role=remote")),
				},
			},
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}},
				Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}}},
			}},
		}},
	}
	require.NoError(b, rule.ValidateAndSanitize())
	repo.ReplaceByResource(policyutils.RulesToPolicyEntries(api.Rules{rule}), "ads-benchmark")

	initialIdentities := benchmarkRemoteIdentities(benchmarkMaxIdentityCount - benchmarkIdentityBatchSize)
	<-updater.UpdateIdentities(initialIdentities, nil)

	kvstoreSynchronizer := ipcache.NewIPIdentitySynchronizer(
		logger,
		kvstore.SetupDummy(b, kvstore.DisabledBackendName),
	)
	localIdentity := identity.NewIdentityFromLabelArray(9_001, labels.ParseLabelArray("k8s:bar"))
	for i := range benchmarkEndpointCount {
		state := models.EndpointState(endpoint.StateWaitingForIdentity)
		model := &models.EndpointChangeRequest{
			State: &state,
			Properties: map[string]any{
				endpointtypes.PropertyFakeEndpoint: false,
			},
		}
		ep, err := endpoint.NewEndpointFromChangeModel(endpoint.EndpointParams{
			Logger:              logger,
			EPBuildQueue:        &endpoint.MockEndpointBuildQueue{},
			Orchestrator:        &fakeendpoint.FakeOrchestrator{},
			PolicyRepo:          repo,
			PolicyFetcher:       computer,
			IdentityManager:     idmgr,
			IPSecConfig:         fakeipsec.Config{},
			WgConfig:            &fakewireguard.Config{},
			CTMapGC:             ctmap.NewFakeGCRunner(),
			Allocator:           testidentity.NewMockIdentityAllocator(nil),
			KVStoreSynchronizer: kvstoreSynchronizer,
		}, nil, endpointProxy, model, nil)
		require.NoError(b, err)

		ep.IPv4 = netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+1))
		ep.SetIdentity(localIdentity)
		require.NoError(b, manager.AddEndpoint(ep))
		b.Cleanup(ep.Stop)

		success := <-ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
			Reason:            regeneration.ReasonPolicyUpdate,
			RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		})
		require.True(b, success)
	}

	policies := backend.networkPolicies()
	require.Len(b, policies, benchmarkEndpointCount)
	for _, networkPolicy := range policies {
		require.Len(b, networkPolicy.EgressPerPortPolicies, 1)
	}
	requireBenchmarkRemotePolicyCount(b, policies, benchmarkMaxIdentityCount-benchmarkIdentityBatchSize)
	benchmarkEnvoy := backend.startEnvoy(b)

	return &identityUpdateBenchmark{
		cacheStats:      backend.stats,
		serverStats:     backend.serverStats,
		envoy:           benchmarkEnvoy,
		updater:         updater,
		networkPolicies: backend.networkPolicies,
	}
}

func requireBenchmarkRemotePolicyCount(b *testing.B, policies []*cilium.NetworkPolicy, expected int) {
	b.Helper()
	require.Len(b, policies, benchmarkEndpointCount)
	for _, networkPolicy := range policies {
		var l7Policy *cilium.PortNetworkPolicy
		for _, portPolicy := range networkPolicy.EgressPerPortPolicies {
			if portPolicy.Port == 80 {
				l7Policy = portPolicy
				break
			}
		}
		require.NotNil(b, l7Policy)
		require.Len(b, l7Policy.Rules, 1)
		require.Len(b, l7Policy.Rules[0].RemotePolicies, expected)
	}
}

func benchmarkRemoteIdentities(count int) identity.IdentityMap {
	identities := make(identity.IdentityMap, count)
	remoteLabels := labels.ParseLabelArray("k8s:role=remote")
	for i := range count {
		identities[benchmarkFirstRemoteID+identity.NumericIdentity(i)] = remoteLabels
	}
	return identities
}

// BenchmarkIdentityUpdateToXDSServer exercises the production path from
// IdentityUpdater.UpdateIdentities through SelectorCache, EndpointManager,
// Endpoint.ApplyPolicyMapChanges, the selected xDS server's UpdateNetworkPolicy,
// cilium.NetworkPolicy construction, and its production cache update.
//
// The workload is taken from issue #48548: 184 L7 endpoint policies, a widest
// selector matching 1,530 identities, and a singleton identityUpdater batch.
// The batch size follows the steady-state allocator call sites, which submit
// one identity per UpdateIdentities call; the issue's 100 identities/hour are
// far enough apart that the zero-interval trigger normally cannot fold them.
//
// Each mode starts with a client that has ACKed the fixture's initial policy and
// is waiting for the next update. The simulated client takes one second to
// process each response before ACKing and requesting again, so updates produced
// during that interval are folded according to the production cache's behavior.
// ADS uses a real go-control-plane SotW watch. The legacy modes observe their
// shared versioned cache and use the production ACK observer; protocol envelope
// marshaling remains outside this producer-side benchmark.
// The benchmark timer stops once all endpoint UpdateNetworkPolicy calls return,
// after NetworkPolicy construction and cache mutation. ACK completion is still
// awaited between batches, but simulated Envoy processing time is not measured.
//
// Both workloads use the same L7 policy. The network-policy-stable workload
// churns an unrelated identity, while network-policy-churn adds/removes an
// identity that matches the L7 rule's remote selector. Both still execute the
// complete endpoint policy update path, and both outcomes are asserted after
// the timed loop.
//
// There is intentionally no benchmark-owned "pooled" implementation. Every
// mode invokes the same stable production entry point, so future production
// batching will be measured without duplicating it here. cache-updates
// and xds-responses make publication and delivery amplification visible.
//
// This benchmark requires a count-based -benchtime. Duration-based automatic
// calibration sees only the producer time and therefore schedules many legacy
// iterations, even though every iteration must still await the excluded
// one-second Envoy processing delay before starting the next batch.
//
// Run with:
//
//	GOMAXPROCS=1 go test ./pkg/envoy -run '^$' \
//	  -bench '^BenchmarkIdentityUpdateToXDSServer$' \
//	  -benchmem -benchtime=1x -count=1
func BenchmarkIdentityUpdateToXDSServer(b *testing.B) {
	benchTime := flag.Lookup("test.benchtime")
	if benchTime == nil || !strings.HasSuffix(benchTime.Value.String(), "x") {
		b.Fatalf("this benchmark requires a count-based -benchtime; use -benchtime=1x")
	}

	workloads := []benchmarkPolicyWorkload{
		{
			name:           "network-policy-stable",
			identityLabels: labels.ParseLabelArray("k8s:role=unrelated"),
		},
		{
			name:              "network-policy-churn",
			identityLabels:    labels.ParseLabelArray("k8s:role=remote"),
			expectPolicyChurn: true,
		},
	}
	modes := []struct {
		name string
		mode envoyconfig.XDSMode
	}{
		{name: "go-control-plane-ads", mode: envoyconfig.EnvoyXDSModeADS},
		{name: "legacy-sotw", mode: envoyconfig.EnvoyXDSModeSplit},
		{name: "legacy-delta", mode: envoyconfig.EnvoyXDSModeDeltaSplit},
	}

	for _, workload := range workloads {
		b.Run(workload.name, func(b *testing.B) {
			for _, benchmarkMode := range modes {
				b.Run(benchmarkMode.name, func(b *testing.B) {
					fixture := newIdentityUpdateBenchmark(b, benchmarkMode.mode)
					toggled := identity.IdentityMap{
						benchmarkFirstRemoteID + benchmarkMaxIdentityCount - 1: workload.identityLabels,
					}
					add := true

					fixture.cacheStats.reset()
					fixture.serverStats.reset()
					fixture.envoy.reset()
					b.ReportAllocs()
					b.ResetTimer()

					for b.Loop() {
						completedNetworkPolicies := fixture.serverStats.completedNetworkPolicies()
						var updateDone <-chan struct{}
						if add {
							updateDone = fixture.updater.UpdateIdentities(toggled, nil)
						} else {
							updateDone = fixture.updater.UpdateIdentities(nil, toggled)
						}

						// UpdateIdentities closes updateDone only after Envoy has ACKed
						// the response. End the measured producer work when every
						// endpoint has returned from the production xDS update instead,
						// then exclude the simulated Envoy processing delay while still
						// waiting for the transaction to finish before the next batch.
						target := completedNetworkPolicies + benchmarkEndpointCount
						require.NoError(b, fixture.serverStats.waitForNetworkPolicies(b.Context(), target))
						b.StopTimer()
						<-updateDone
						b.StartTimer()
						add = !add
					}

					b.StopTimer()
					require.NoError(b, fixture.envoy.err())
					expectedRemotePolicies := benchmarkMaxIdentityCount - benchmarkIdentityBatchSize
					if workload.expectPolicyChurn && b.N%2 != 0 {
						expectedRemotePolicies = benchmarkMaxIdentityCount
					}
					requireBenchmarkRemotePolicyCount(b, fixture.networkPolicies(), expectedRemotePolicies)
					b.ReportMetric(benchmarkIdentityBatchSize, "identities")
					b.ReportMetric(float64(benchmarkEndpointCount), "endpoints")
					fixture.serverStats.report(b)
					fixture.cacheStats.report(b)
					fixture.envoy.report(b)
				})
			}
		})
	}
}
