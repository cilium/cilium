// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

func TestNewADSServer(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		metrics:              nil,
	}

	server := newTestADSServer(t, logger, nil, nil, config, nil, nil)

	require.NotNil(t, server)
	require.NotNil(t, server.logger)
	require.NotNil(t, server.cache)
	assert.NotEmpty(t, server.socketPath)
	assert.NotEmpty(t, server.accessLogPath)
	require.True(t, server.cache.HasNode(localNodeID))
	require.Empty(t, createADSWatchResponse(t, server.cache, ListenerTypeURL, "").GetReturnedResources())
}

func TestNewADSServerRequiresKnownLocalNode(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	cache := xdsnew.NewCache(logger)
	server, err := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	require.ErrorContains(t, err, "is not initialized")
	require.Nil(t, server, "a server without initialized local state must not be exposed")
}

func TestAddListener(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wait      bool
		restoring bool
	}{
		{name: "ack", wait: true},
		{name: "restoring", wait: true, restoring: true},
		{name: "no-wait"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var restorer promise.Promise[endpointstate.Restorer]
			if tc.restoring {
				_, restorer = promise.New[endpointstate.Restorer]()
			}
			server, cache := newADSServerFixture(t, restorer)
			var wg *completion.WaitGroup
			var done <-chan error
			if tc.wait {
				wg = completion.NewWaitGroup(t.Context())
			}
			require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg))
			if tc.wait {
				done = waitForADSCompletion(t, wg)
			}
			actual := cachedListener(t, cache, localNodeID, "test-listener")
			expected := server.getListenerConf("test-listener", policy.ParserTypeHTTP, 8080, false, false)
			require.True(t, proto.Equal(expected, actual))
			require.Len(t, actual.ListenerFilters, 2)
			require.Equal(t, "envoy.filters.listener.tls_inspector", actual.ListenerFilters[0].Name)
			require.Equal(t, "cilium.bpf_metadata", actual.ListenerFilters[1].Name)
			require.Len(t, actual.FilterChains, 2)

			if tc.wait {
				requireADSCompletionPending(t, done)
				response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
				delivered := deliverADSResponse(t, cache, 1, response)
				requireADSCompletionPending(t, done)
				replyADSResponse(t, cache, 1, response, delivered, "")
				require.NoError(t, <-done)
			}
		})
	}
}

func TestNoOpListenerAlreadyAcceptedDoesNotWaitForUnrelatedListener(t *testing.T) {
	_, restorer := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorer)
	first := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener-1": {Name: "listener-1"},
	}}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), first))
	accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	second := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener-2": {Name: "listener-2"},
	}}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), second))
	server.markRestoreCompleted()
	response := createADSWatchResponse(t, cache, ListenerTypeURL, accepted)
	delivered := deliverADSResponse(t, cache, 1, response)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	// The first listener's ACK remains sufficient even while the response
	// containing the unrelated second listener has not been acknowledged.
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), first))
	replyADSResponse(t, cache, 1, response, delivered, "")
}

func TestUpdateEnvoyResourcesNoOpListenerWaitsForCurrentACK(t *testing.T) {
	resources := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener": {Name: "listener"},
	}}
	// Seed without a wait, then exercise Update's internally owned no-op wait.
	server, cache := newSeededADSServerFixture(t, resources)
	response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	delivered := deliverADSResponse(t, cache, 1, response)
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	// A synchronous timeout proves the semantic no-op really waits, without
	// racing an ACK against the update goroutine's completion registration.
	require.ErrorIs(t, server.UpdateEnvoyResources(ctx, resources, resources), context.DeadlineExceeded)
	replyADSResponse(t, cache, 1, response, delivered, "")
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), resources, resources))
}

func TestUpdateEnvoyResourcesWaitOutcome(t *testing.T) {
	for _, outcome := range []string{"ack", "nack", "nack-after-cds-ack", "cluster-nack", "cluster-nack-after-lds-ack", "canceled", "deadline", "superseded-nack"} {
		t.Run(outcome, func(t *testing.T) {
			old := xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"retired": {Name: "retired", StatPrefix: "cached"}},
				Clusters:  map[string]*envoy_config_cluster.Cluster{"retired": {Name: "retired", AltStatName: "cached"}},
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"retired": {ClusterName: "retired", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{Priority: 1}}}},
				Routes:    map[string]*envoy_config_route.RouteConfiguration{"retired": {Name: "retired", VirtualHosts: []*envoy_config_route.VirtualHost{{Name: "cached"}}}},
				Secrets:   map[string]*envoy_config_tls.Secret{"retired": {Name: "retired", Type: &envoy_config_tls.Secret_TlsCertificate{}}},
			}
			expectedRetired := typeurl.Slots[proto.Message]{
				typeurl.Listener: old.Listeners["retired"],
				typeurl.Cluster:  old.Clusters["retired"],
				typeurl.Endpoint: old.Endpoints["retired"],
				typeurl.Route:    old.Routes["retired"],
				typeurl.Secret:   old.Secrets["retired"],
			}
			old.Secrets["related"] = &envoy_config_tls.Secret{Name: "related", Type: &envoy_config_tls.Secret_TlsCertificate{}}
			server, cache := newSeededADSServerFixture(t, old)
			// The caller's old resources may be stale or already absent. Recover
			// the actual cached values, without creating entries which never existed.
			old.Listeners["retired"] = &envoy_config_listener.Listener{Name: "retired"}
			old.Clusters["retired"] = &envoy_config_cluster.Cluster{Name: "retired"}
			old.Endpoints["retired"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "retired"}
			old.Routes["retired"] = &envoy_config_route.RouteConfiguration{Name: "retired"}
			old.Secrets["retired"] = &envoy_config_tls.Secret{Name: "retired"}
			old.Listeners["absent"] = &envoy_config_listener.Listener{Name: "absent"}
			old.Clusters["absent"] = &envoy_config_cluster.Cluster{Name: "absent"}
			old.Endpoints["absent"] = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "absent"}
			old.Routes["absent"] = &envoy_config_route.RouteConfiguration{Name: "absent"}
			old.Secrets["absent"] = &envoy_config_tls.Secret{Name: "absent"}
			// This name will be upserted, but also did not exist before the call.
			old.Routes["routeConfig1"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig1"}
			timeout := time.Second
			if outcome == "deadline" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			resources := adsDefaultResources()
			resources.Listeners["listener1"] = adsTestListener(80)
			resources.Routes["retired"] = nil // Explicit removal also needs its actual prior value.
			resources.Secrets["related"] = &envoy_config_tls.Secret{Name: "related"}
			done := startADSResourceUpdate(server, ctx, old, resources)
			require.Eventually(t, func() bool {
				return cache.GetResource(localNodeID, typeurl.Listener, "listener1") != nil
			}, time.Second, time.Millisecond)
			requireADSCompletionPending(t, done)

			// Other server writers must run while Update waits. Their entries must
			// also survive its failure, including a replacement of a touched name.
			unrelated := xds.NewResources()
			unrelated.Secrets["unrelated"] = &envoy_config_tls.Secret{Name: "unrelated"}
			if outcome == "superseded-nack" {
				unrelated.Secrets["related"] = &envoy_config_tls.Secret{Name: "related", Type: &envoy_config_tls.Secret_TlsCertificate{}}
				unrelated.Secrets["retired"] = &envoy_config_tls.Secret{Name: "retired", Type: &envoy_config_tls.Secret_GenericSecret{}}
				expectedRetired[typeurl.Secret] = unrelated.Secrets["retired"]
			}
			updated := make(chan error, 1)
			go func() {
				for _, secret := range unrelated.Secrets {
					if err := server.UpsertSecret(ctx, secret); err != nil {
						updated <- err
						return
					}
				}
				updated <- nil
			}()
			select {
			case err := <-updated:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("ACK wait blocked another server update")
			}

			switch outcome {
			case "ack":
				ackADSResourceVersionFrom(t, cache, 1, ClusterTypeURL, "")
				requireADSCompletionPending(t, done)
				ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			case "nack", "nack-after-cds-ack", "superseded-nack":
				if outcome == "nack-after-cds-ack" {
					ackADSResourceVersionFrom(t, cache, 1, ClusterTypeURL, "")
					requireADSCompletionPending(t, done)
				}
				nackADSResourceVersion(t, cache, 1, ListenerTypeURL, "", "rejected listener")
			case "cluster-nack", "cluster-nack-after-lds-ack":
				// CDS failures must fail the whole update, including after LDS acceptance.
				if outcome == "cluster-nack-after-lds-ack" {
					ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
					requireADSCompletionPending(t, done)
				}
				nackADSResourceVersion(t, cache, 1, ClusterTypeURL, "", "rejected cluster")
			case "canceled":
				cancel()
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				t.Fatal("update did not finish after its wait outcome")
			}
			switch outcome {
			case "ack":
				require.NoError(t, err)
				requireCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
				requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
			case "canceled":
				require.ErrorIs(t, err, context.Canceled)
			case "deadline":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case "cluster-nack", "cluster-nack-after-lds-ack":
				require.ErrorContains(t, err, "rejected cluster")
			default:
				require.ErrorContains(t, err, "rejected listener")
			}
			if outcome != "ack" {
				requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
				requireNoCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
				requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
				requireNoCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
				requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
				if outcome != "superseded-nack" {
					require.Same(t, old.Secrets["related"], cache.GetResource(localNodeID, typeurl.Secret, "related"))
				}
			}
			for name, secret := range unrelated.Secrets {
				require.Same(t, secret, cache.GetResource(localNodeID, typeurl.Secret, name))
			}
			for _, typeURL := range []typeurl.Index{typeurl.Listener, typeurl.Cluster, typeurl.Endpoint, typeurl.Route, typeurl.Secret} {
				require.Nil(t, cache.GetResource(localNodeID, typeURL, "absent"), "%s must not be created during recovery", typeURL.URL())
				if outcome == "ack" {
					require.Nil(t, cache.GetResource(localNodeID, typeURL, "retired"), "%s removal must remain on success", typeURL.URL())
				} else {
					require.True(t, proto.Equal(expectedRetired[typeURL], cache.GetResource(localNodeID, typeURL, "retired")), "%s must restore its previous cached value", typeURL.URL())
				}
			}
		})
	}
}

func TestAddDiagnosticListener(t *testing.T) {
	for _, tc := range []struct {
		name     string
		port     uint16
		add      func(*adsServer, context.Context, uint16, *completion.WaitGroup)
		expected func(*adsServer, uint16) *envoy_config_listener.Listener
	}{
		{name: "envoy-admin-listener", port: 9000, add: (*adsServer).AddAdminListener, expected: (*adsServer).getAdminListenerConfig},
		{name: "envoy-prometheus-metrics-listener", port: 9001, add: (*adsServer).AddMetricsListener, expected: (*adsServer).getMetricsListenerConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tt := range []struct {
				name   string
				wait   bool
				reject bool
				cancel bool
				repeat bool
			}{
				{name: "ack", wait: true},
				{name: "repeated-add", wait: true, repeat: true},
				{name: "repeated-add-nack", wait: true, repeat: true, reject: true},
				{name: "nack", wait: true, reject: true},
				{name: "nack-without-wait", reject: true},
				{name: "canceled-then-nack", wait: true, reject: true, cancel: true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					server, cache := newADSServerFixture(t)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					var wg *completion.WaitGroup
					if tt.wait {
						wg = completion.NewWaitGroup(ctx)
						t.Cleanup(wg.Cancel)
					}
					tc.add(server, ctx, 0, wg)
					requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, tc.name)
					tc.add(server, ctx, tc.port, wg)
					if tt.repeat {
						tc.add(server, ctx, tc.port, wg)
					}
					var done <-chan error
					if tt.wait {
						done = waitForADSCompletion(t, wg)
					}
					actual := cachedListener(t, cache, localNodeID, tc.name)
					require.True(t, proto.Equal(tc.expected(server, tc.port), actual))
					require.Len(t, actual.FilterChains, 1)
					if tc.name == "envoy-admin-listener" {
						require.Len(t, actual.FilterChains[0].Filters, 1)
						require.Equal(t, "envoy.filters.network.http_connection_manager", actual.FilterChains[0].Filters[0].Name)
					}
					response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
					delivered := deliverADSResponse(t, cache, 1, response)
					if tt.cancel {
						cancel()
						require.ErrorIs(t, <-done, context.Canceled)
						// Abandoning the caller's wait leaves the listener configured.
						// Only an actual NACK triggers response-owned recovery.
						require.Same(t, actual, cachedListener(t, cache, localNodeID, tc.name))
					}
					var rejection string
					if tt.reject {
						rejection = "listener bind failed"
					}
					replyADSResponse(t, cache, 1, response, delivered, rejection)
					if tt.wait && !tt.cancel {
						if tt.reject {
							require.ErrorContains(t, <-done, rejection)
						} else {
							require.NoError(t, <-done)
						}
					}
					if tt.reject {
						requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, tc.name)
					} else {
						require.Same(t, actual, cachedListener(t, cache, localNodeID, tc.name))
					}
				})
			}
		})
	}
}

func TestProgrammaticResourcesSurviveNACK(t *testing.T) {
	for _, source := range []string{"proxy-listener", "secret-sync", "nphds"} {
		t.Run(source, func(t *testing.T) {
			_, restorer := promise.New[endpointstate.Restorer]()
			server, cache := newADSServerFixture(t, restorer)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			var typeURL, name string
			cec := xds.NewResources()
			switch source {
			case "proxy-listener":
				typeURL, name = ListenerTypeURL, "internal"
				require.NoError(t, server.AddListener(t.Context(), name, policy.ParserTypeHTTP, 12345, false, false, wg))
				cec.Listeners["cec"] = server.getListenerConf("cec", policy.ParserTypeHTTP, 12346, false, false)
			case "secret-sync":
				typeURL, name = SecretTypeURL, "test/test"
				syncer := newSecretSyncer(server.logger, server)
				require.NoError(t, syncer.upsertK8sSecretV1(t.Context(), testSecret()))
				cec.Secrets["cec"] = &envoy_config_tls.Secret{Name: "cec"}
			case "nphds":
				typeURL, name = NetworkPolicyHostsTypeURL, "123"
				adapter := newNPHDSCacheAdapter(server.logger, server)
				require.NoError(t, adapter.handleIPUpsert(name, "192.0.2.1/32", 123))
			}
			index, supported := typeurl.FromURL(typeURL)
			require.True(t, supported)
			internal := cache.GetResource(localNodeID, index, name)
			require.NotNil(t, internal)
			if source != "nphds" {
				// Restoration admits CEC resources without waiting, but keeps
				// independent response recovery enabled after Update returns.
				require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), cec))
				server.markRestoreCompleted()
			}
			nackADSResourceVersion(t, cache, 1, typeURL, "", "rejected response")
			require.Same(t, internal, cache.GetResource(localNodeID, index, name))
			requireNoCachedResource(t, cache, localNodeID, typeURL, "cec")
			if source == "proxy-listener" {
				require.ErrorContains(t, wg.Wait(), "rejected response")
			}
		})
	}
}

func TestRemoveListener(t *testing.T) {
	for _, references := range []int{1, 2} {
		t.Run(fmt.Sprintf("references=%d", references), func(t *testing.T) {
			server, cache := newADSServerFixture(t)
			for range references {
				require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil))
			}
			version := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			for remaining := references - 1; remaining >= 0; remaining-- {
				wg := completion.NewWaitGroup(t.Context())
				server.RemoveListener(t.Context(), "test-listener", wg)
				done := waitForADSCompletion(t, wg)
				if remaining != 0 {
					require.NotNil(t, cachedListener(t, cache, localNodeID, "test-listener"))
				} else {
					requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")
					requireADSCompletionPending(t, done)
					ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, version)
				}
				require.NoError(t, <-done)
			}
		})
	}
}

func TestRemoveListenerWaitsForACKAfterNACK(t *testing.T) {
	server, cache := newADSServerFixture(t)
	require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil))
	accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	wg := completion.NewWaitGroup(t.Context())
	server.RemoveListener(t.Context(), "test-listener", wg)
	done := waitForADSCompletion(t, wg)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")
	// The NACK leaves the listener removed and its caller wait pending. The
	// next response must ACK the removal before the caller can proceed.
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, accepted, "rejected listener removal")
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")
	requireADSCompletionPending(t, done)
	ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, accepted)
	require.NoError(t, <-done)
	// Re-acquiring and releasing one reference must delete the resource again.
	// A reference resurrected by NACK recovery would leave it live.
	require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil))
	server.RemoveListener(t.Context(), "test-listener", nil)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")
}

func TestUpsertSecret(t *testing.T) {
	server, cache := newADSServerFixture(t)
	for _, value := range []string{"initial", "updated"} {
		secret := &envoy_config_tls.Secret{
			Name: "secret1",
			Type: &envoy_config_tls.Secret_GenericSecret{GenericSecret: &envoy_config_tls.GenericSecret{
				Secret: &envoy_config_core_v3.DataSource{Specifier: &envoy_config_core_v3.DataSource_InlineString{InlineString: value}},
			}},
		}
		require.NoError(t, server.UpsertSecret(t.Context(), secret))
		require.True(t, proto.Equal(secret, cache.GetResource(localNodeID, typeurl.Secret, secret.Name)))
	}
}

func TestUpdateEnvoyResources(t *testing.T) {
	old := adsDefaultResources()
	server, cache := newSeededADSServerFixture(t, old)
	requireCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	for _, ep := range adsTestEndpoints() {
		requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, strconv.FormatUint(ep.id, 10))
	}
	policy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 40, ipv4: "10.0.0.1"})
	next := adsDefaultResources()
	next.Secrets = nil
	next.Routes["routeConfig2"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig2"}
	next.Listeners["listener1"].FilterChains[0].Filters = append(next.Listeners["listener1"].FilterChains[0].Filters,
		&envoy_config_listener.Filter{Name: "envoy.http_connection_manager", ConfigType: &envoy_config_listener.Filter_TypedConfig{
			TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{StatPrefix: "http_proxy",
				RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{RouteConfigName: "routeConfig2"}}}),
		}})
	done := startADSResourceUpdate(server, t.Context(), old, next)
	require.Eventually(t, func() bool {
		return cache.GetResource(localNodeID, typeurl.Route, "routeConfig2") != nil
	}, time.Second, time.Millisecond)
	ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	ackADSResourceVersionFrom(t, cache, 1, ClusterTypeURL, "")
	require.NoError(t, <-done)
	requireCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig2")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	require.Same(t, policy, cachedNetworkPolicy(t, cache, localNodeID, "40"), "Envoy resource updates must not mutate NPDS")
}

func TestUpdateEnvoyResourcesListenerAddressChange(t *testing.T) {
	addressChanges := []struct {
		name        string
		oldListener *envoy_config_listener.Listener
		newListener *envoy_config_listener.Listener
		reusePort   bool
	}{
		{
			name:        "additional address changed",
			oldListener: adsTestListener(80, 8443),
			newListener: adsTestListener(80, 8444),
		},
		{
			name:        "primary port changed",
			oldListener: adsTestListener(80, 8443),
			newListener: adsTestListener(81, 8443),
		},
		{
			name:        "additional address changed with port reuse",
			oldListener: adsTestListener(80, 8443),
			newListener: adsTestListener(80, 8444),
			reusePort:   true,
		},
	}

	for _, addressChange := range addressChanges {
		t.Run(addressChange.name, func(t *testing.T) {
			if addressChange.reusePort {
				addressChange.oldListener.EnableReusePort = wrapperspb.Bool(true)
				addressChange.newListener.EnableReusePort = wrapperspb.Bool(true)
			}
			oldResources := adsTestResources(addressChange.oldListener)
			server, cache := newSeededADSServerFixture(t, oldResources)

			newResources := adsTestResources(addressChange.newListener)

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- server.UpdateEnvoyResources(ctx, oldResources, newResources)
			}()

			deleteVersion := ""
			if !addressChange.reusePort {
				require.Eventually(t, func() bool {
					return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil
				}, time.Second, 10*time.Millisecond)
				deleteVersion = ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			}

			require.Eventually(t, func() bool {
				listener, _ := cache.GetResource(localNodeID, typeurl.Listener, "listener1").(*envoy_config_listener.Listener)
				return listener != nil && listenerAddressesEqual(listener, newResources.Listeners["listener1"])
			}, time.Second, 10*time.Millisecond)
			replaceVersion := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, deleteVersion)
			require.NotEqual(t, deleteVersion, replaceVersion)

			require.NoError(t, <-result)

		})
	}

}

func TestUpdateEnvoyResourcesDuringRestoreDoesNotStageListenerDeletion(t *testing.T) {
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorerPromise)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), oldResources))
	newResources := adsTestResources(adsTestListener(81, 8444))
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), oldResources, newResources))
	require.True(t, proto.Equal(newResources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))

	ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")

}

func TestUpdateEnvoyResourcesAddressChangePreservesNewerListenerOnDelayedNACK(t *testing.T) {
	_, restorer := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorer)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	initial := adsTestResources(adsTestListener(80, 8442))
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), initial))
	accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	tracked := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpdateEnvoyResources(ctx, initial, tracked))
	server.markRestoreCompleted()
	oldResponse := createADSWatchResponse(t, cache, ListenerTypeURL, accepted)
	oldDelivery := deliverADSResponse(t, cache, 1, oldResponse)

	desired := adsTestResources(adsTestListener(80, 8444))
	result := make(chan error, 1)
	go func() { result <- server.UpdateEnvoyResources(ctx, tracked, desired) }()
	require.Eventually(t, func() bool { return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil }, time.Second, time.Millisecond)
	deleted := ackADSResourceVersionFrom(t, cache, 2, ListenerTypeURL, accepted)
	require.Eventually(t, func() bool {
		listener, _ := cache.GetResource(localNodeID, typeurl.Listener, "listener1").(*envoy_config_listener.Listener)
		return listener != nil && listenerAddressesEqual(listener, desired.Listeners["listener1"])
	}, time.Second, time.Millisecond)
	ackADSResourceVersionFrom(t, cache, 2, ListenerTypeURL, deleted)
	require.NoError(t, <-result)
	replyADSResponse(t, cache, 1, oldResponse, oldDelivery, "rejected older listener")
	require.True(t, proto.Equal(desired.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))
}

func TestUpdateEnvoyResourcesRestoresResourcesAfterAddressChangeFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement bool
		rejection   string
		canceled    bool
		cluster     bool
	}{
		{name: "deletion-nack", rejection: "rejected listener deletion"},
		{name: "deletion-timeout"},
		{name: "replacement-canceled", replacement: true, canceled: true},
		{name: "replacement-nack", replacement: true, rejection: "rejected listener"},
		{name: "replacement-cluster-nack", replacement: true, rejection: "rejected cluster", cluster: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := adsDefaultResources()
			old.Listeners["listener1"] = adsTestListener(80, 8443)
			old.Listeners["retired"] = &envoy_config_listener.Listener{Name: "retired"}
			old.Routes["retired"] = &envoy_config_route.RouteConfiguration{Name: "retired"}
			server, cache := newSeededADSServerFixture(t, old)
			accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			originalListener := old.Listeners["listener1"]
			old.Listeners["listener1"] = proto.Clone(originalListener).(*envoy_config_listener.Listener)
			old.Listeners["listener1"].StatPrefix = "stale"
			old.Listeners["absent"] = adsTestListener(81)
			old.Listeners["absent"].Name = "absent"
			next := adsTestResources(adsTestListener(80, 8444))
			next.Listeners["absent"] = adsTestListener(82)
			next.Listeners["absent"].Name = "absent"
			if tc.cluster {
				next.Clusters["replacement"] = &envoy_config_cluster.Cluster{Name: "replacement"}
			}
			timeout := 5 * time.Second
			if tc.name == "deletion-timeout" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- server.UpdateEnvoyResources(ctx, old, next) }()
			if tc.name != "deletion-timeout" {
				require.Eventually(t, func() bool { return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil }, time.Second, time.Millisecond)
				if tc.replacement {
					accepted = ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, accepted)
					require.Eventually(t, func() bool { return cache.GetResource(localNodeID, typeurl.Listener, "listener1") != nil }, time.Second, time.Millisecond)
				}
				if tc.canceled {
					cancel()
				} else {
					typeURL, version := ListenerTypeURL, accepted
					if tc.cluster {
						typeURL, version = ClusterTypeURL, ""
					}
					response := createADSWatchResponse(t, cache, typeURL, version)
					delivered := deliverADSResponse(t, cache, 1, response)
					request := proto.Clone(response.GetRequest()).(*envoy_service_discovery.DiscoveryRequest)
					request.ResponseNonce = delivered.GetNonce()
					request.ErrorDetail = &status.Status{Message: tc.rejection}
					// This runs concurrently with UpdateEnvoyResources waiting
					// under the ADS mutex. Bound the wait to expose a deadlock.
					nacked := make(chan error, 1)
					go func() { nacked <- cache.GetCompletionCallbacks().OnStreamRequest(1, request) }()
					select {
					case err := <-nacked:
						require.NoError(t, err)
					case <-time.After(time.Second):
						t.Fatal("listener NACK deadlocked with the ADS update")
					}
					if !tc.replacement {
						// The removal remains desired and its wait survives NACK.
						// Cancellation must still restore the caller's transaction.
						requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
						select {
						case err := <-result:
							t.Fatalf("removal NACK prematurely ended address update: %v", err)
						default:
						}
						cancel()
					}
				}
			}
			select {
			case err := <-result:
				switch {
				case tc.canceled || (!tc.replacement && tc.rejection != ""):
					require.ErrorIs(t, err, context.Canceled)
				case tc.rejection != "":
					require.ErrorContains(t, err, tc.rejection)
				default:
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			case <-time.After(time.Second):
				t.Fatal("listener address update did not finish")
			}
			require.True(t, proto.Equal(originalListener, cache.GetResource(localNodeID, typeurl.Listener, "listener1")))
			requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "absent")
			require.Same(t, old.Listeners["retired"], cachedListener(t, cache, localNodeID, "retired"))
			require.Same(t, old.Clusters["cluster1"], cache.GetResource(localNodeID, typeurl.Cluster, "cluster1"))
			require.Same(t, old.Endpoints["cluster1"], cache.GetResource(localNodeID, typeurl.Endpoint, "cluster1"))
			require.Same(t, old.Routes["retired"], cache.GetResource(localNodeID, typeurl.Route, "retired"))
			require.Same(t, old.Secrets["secret1"], cache.GetResource(localNodeID, typeurl.Secret, "secret1"))
			requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "replacement")
		})
	}
}

func TestUpdateEnvoyResourcesRetriesReplacementBindFailure(t *testing.T) {
	oldResources := adsTestResources(adsTestListener(80, 8443))
	server, cache := newSeededADSServerFixture(t, oldResources)
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources)
	}()

	require.Eventually(t, func() bool {
		return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil
	}, time.Second, 10*time.Millisecond)
	deleteVersion := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")

	require.Eventually(t, func() bool {
		return cache.GetResource(localNodeID, typeurl.Listener, "listener1") != nil
	}, time.Second, 10*time.Millisecond)
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, deleteVersion, "cannot bind: Address already in use")

	// The rejected desired version is first replaced with the accepted deletion
	// contents under a new generation version. ACK that rollback response before
	// opening the watch which consumes the retried replacement.
	require.Eventually(t, func() bool {
		return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil
	}, time.Second, 10*time.Millisecond)
	rollbackVersion := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, deleteVersion)
	require.NotEqual(t, deleteVersion, rollbackVersion)
	retryResponse := createADSWatchResponse(t, cache, ListenerTypeURL, rollbackVersion)
	retry := deliverADSResponse(t, cache, 1, retryResponse)
	require.Len(t, retry.Resources, 1)
	replyADSResponse(t, cache, 1, retryResponse, retry, "")

	require.NoError(t, <-result)
	listener := cachedListener(t, cache, localNodeID, "listener1")
	require.True(t, listenerAddressesEqual(listener, newResources.Listeners["listener1"]))

}

func TestUpdateEnvoyResourcesWaitScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		baseline    string
		cluster     bool
		noListeners bool
		wait        bool
	}{
		{name: "accepted-listener-and-cluster", baseline: "accepted-listener", cluster: true, wait: true},
		{name: "listener", wait: true},
		{name: "cluster-and-listener", cluster: true, wait: true},
		{name: "unacked-resources-with-unrelated-changes", baseline: "unacked-resources", cluster: true, wait: true},
		{name: "clusters-only", cluster: true, noListeners: true},
		{name: "removals-only", baseline: "unacked-resources", noListeners: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			old := xds.NewResources()
			if tc.baseline == "accepted-listener" {
				old.Listeners["listener1"] = adsDefaultResources().Listeners["listener1"]
			} else if tc.baseline == "unacked-resources" {
				old = adsDefaultResources()
			}
			server, cache := newSeededADSServerFixture(t, old)
			if tc.baseline == "accepted-listener" {
				ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			}
			next := xds.NewResources()
			next.Listeners["listener1"] = adsDefaultResources().Listeners["listener1"]
			if tc.cluster {
				next = adsDefaultResources()
			}
			if tc.baseline == "unacked-resources" {
				next.Routes["routeConfig2"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig2"}
				next.Clusters["cluster2"] = &envoy_config_cluster.Cluster{Name: "cluster2",
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS}}
			}
			if tc.noListeners {
				next.Listeners = nil
				if !tc.cluster {
					next = xds.NewResources()
				}
			}
			done := startADSResourceUpdate(server, ctx, old, next)
			if tc.wait {
				require.Eventually(t, func() bool {
					if tc.baseline == "unacked-resources" {
						return cache.GetResource(localNodeID, typeurl.Cluster, "cluster2") != nil
					}
					if tc.cluster {
						return cache.GetResource(localNodeID, typeurl.Cluster, "cluster1") != nil
					}
					return cache.GetResource(localNodeID, typeurl.Listener, "listener1") != nil
				}, time.Second, time.Millisecond)
				requireADSCompletionPending(t, done)
				if tc.cluster {
					ackADSResourceVersionFrom(t, cache, 1, ClusterTypeURL, "")
					if tc.baseline != "accepted-listener" {
						requireADSCompletionPending(t, done)
					}
					// RDS remains unacknowledged: it is not a caller-wait dependency.
					deliverADSResponse(t, cache, 1, createADSWatchResponse(t, cache, RouteTypeURL, ""))
				}
				if tc.baseline != "accepted-listener" {
					ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
				}
			}
			require.NoError(t, <-done)
			if tc.baseline == "unacked-resources" && !tc.noListeners {
				requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig2")
				requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster2")
			}
		})
	}
}

func TestDeleteEnvoyResources(t *testing.T) {
	_, restorer := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorer)
	ctx := context.Background()

	xdsResources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{},
		Clusters:  map[string]*envoy_config_cluster.Cluster{},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{},
		Secrets:   map[string]*envoy_config_tls.Secret{},
	}

	// Deleting empty resources should be no-op.
	err := server.DeleteEnvoyResources(ctx, xdsResources)
	assert.NoError(t, err)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireNoCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "40")
	requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")

	// Add some resources and then delete them.
	err = server.UpdateEnvoyResources(ctx, xds.NewResources(), adsDefaultResources())
	assert.NoError(t, err)
	server.markRestoreCompleted()
	policy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 40, ipv4: "10.0.0.1"})

	requireCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	require.Same(t, policy, cachedNetworkPolicy(t, cache, localNodeID, "40"))

	err = server.DeleteEnvoyResources(ctx, adsDefaultResources())
	assert.NoError(t, err)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireNoCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	require.Same(t, policy, cachedNetworkPolicy(t, cache, localNodeID, "40"), "Envoy resource deletion must not mutate NPDS")
	requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireNoCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
}

func TestUpdateNetworkPolicy(t *testing.T) {
	server, cache := newSeededADSServerFixture(t, adsDefaultResources())
	seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 40, ipv4: "10.0.0.1"})
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
	require.NoError(t, err)
	require.NotNil(t, rollback)
	defer rollback.Finalize()
	for _, endpoint := range []*testableEndpointUpdater{{id: 40, ipv4: "10.0.0.1"}, ep} {
		policy := cachedNetworkPolicy(t, cache, localNodeID, strconv.FormatUint(endpoint.id, 10))
		require.Equal(t, endpoint.id, policy.GetEndpointId())
		require.Equal(t, endpoint.GetPolicyNames(), policy.GetEndpointIps())
		requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, endpoint.ipv4)
	}
	requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "nonexistent")
	require.Same(t, ep, server.localEndpointStore.getLocalEndpoint("127.0.0.1"))
}

func TestUpdateNetworkPolicyRollback(t *testing.T) {
	for _, tc := range []struct {
		name          string
		laterEndpoint *testableEndpointUpdater
		nack          bool
	}{
		{name: "caller"},
		{name: "unrelated-endpoint", laterEndpoint: &testableEndpointUpdater{id: 2, ipv4: "127.0.0.2"}},
		{name: "superseded-policy", laterEndpoint: &testableEndpointUpdater{id: 1, ipv4: "127.0.0.2"}},
		{name: "nack-before-caller-revert", nack: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cache := newADSServerFixture(t)
			previous := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 1, ipv4: "192.0.2.1"})
			accepted := ackADSResourceVersionFrom(t, cache, 1, NetworkPolicyTypeURL, "")
			ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
			epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
			err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, epp, nil)
			require.NoError(t, err)
			require.NotNil(t, rollback)
			require.False(t, proto.Equal(previous, cachedNetworkPolicy(t, cache, localNodeID, "1")))
			if tc.laterEndpoint != nil {
				seedADSNetworkPolicy(t, server, tc.laterEndpoint)
			}
			expected := previous
			if tc.laterEndpoint != nil && tc.laterEndpoint.id == 1 {
				expected = cachedNetworkPolicy(t, cache, localNodeID, "1")
			}
			if tc.nack {
				nackADSResourceVersion(t, cache, 1, NetworkPolicyTypeURL, accepted, "rejected policy")
				require.True(t, proto.Equal(previous, cachedNetworkPolicy(t, cache, localNodeID, "1")))
			}
			require.NoError(t, rollback.Revert())
			require.True(t, proto.Equal(expected, cachedNetworkPolicy(t, cache, localNodeID, "1")))
			if tc.laterEndpoint != nil && tc.laterEndpoint.id == 2 {
				requireCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "2")
			}
			// The access-log mapping tracks endpoint existence independently of policy rollback.
			require.Same(t, ep, server.localEndpointStore.getLocalEndpoint("127.0.0.1"))
		})
	}
}

func TestUpdateNetworkPolicyDuringRestoreWaitsForSeededPolicyACK(t *testing.T) {
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorerPromise)

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources))

	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	// Initial endpoint restoration seeds the policy without waiting. A later
	// regeneration of the same policy must still be able to wait for Envoy to
	// accept the seeded policy once a watch causes it to be published.
	err, revertible := server.UpdateNetworkPolicy(t.Context(), mockEp, mockPolicy, nil)
	require.NoError(t, err)
	require.NotNil(t, revertible)
	revertible.Finalize()

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	err, revertible = server.UpdateNetworkPolicy(t.Context(), mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertible)
	revertible.Finalize()

	done := waitForADSCompletion(t, wg)
	requireADSCompletionPending(t, done)

	// Opening the first NPDS watch publishes the accumulated policy changes. The
	// no-op update above must remain pending until Envoy ACKs that snapshot.
	seededVersion := ackADSResourceVersionFrom(t, cache, 1, NetworkPolicyTypeURL, "")
	require.NotEmpty(t, seededVersion)
	require.NoError(t, <-done)
}

func TestUpdateNetworkPolicyWaitCompletesWithoutNPDSListeners(t *testing.T) {
	for _, action := range []string{"never-added", "bulk-delete", "remove-listener", "listener-nack"} {
		t.Run(action, func(t *testing.T) {
			_, restorer := promise.New[endpointstate.Restorer]()
			server, cache := newADSServerFixture(t, restorer)
			require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), adsDefaultResources()))
			var resources xds.Resources
			if action != "never-added" {
				resources = xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
					"npds-listener": server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false),
				}}
				if action == "bulk-delete" || action == "listener-nack" {
					require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources))
				} else {
					require.NoError(t, server.AddListener(t.Context(), "npds-listener", policy.ParserTypeHTTP, 12345, false, false, nil))
				}
			}
			server.markRestoreCompleted()
			wg := completion.NewWaitGroup(t.Context())
			ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
			err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
			require.NoError(t, err)
			require.NotNil(t, rollback)
			defer rollback.Finalize()
			done := waitForADSCompletion(t, wg)
			if action != "never-added" {
				requireADSCompletionPending(t, done)
			}
			switch action {
			case "bulk-delete":
				require.NoError(t, server.DeleteEnvoyResources(t.Context(), resources))
			case "remove-listener":
				server.RemoveListener(t.Context(), "npds-listener", nil)
			case "listener-nack":
				// This exercises the production observer on an asynchronous
				// cache-driven removal, without taking the server mutex.
				nackADSResourceVersion(t, cache, 1, ListenerTypeURL, "", "rejected NPDS listener")
			}
			require.NoError(t, <-done)
			requireCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "1")
		})
	}
}

func TestLastNPDSListenerRemovalKeepsSentPolicyNACKRollback(t *testing.T) {
	_, restorer := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorer)
	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources))
	server.markRestoreCompleted()
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
	require.NoError(t, err)
	require.NotNil(t, rollback)
	response := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, "")
	delivered := deliverADSResponse(t, cache, 1, response)
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), resources))
	require.NoError(t, wg.Wait())
	rollback.Finalize()
	requireCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "1")

	// Releasing the caller wait is not a protocol ACK.
	replyADSResponse(t, cache, 1, response, delivered, "policy rejected after listener removal")
	requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "1")
}

func TestUpdateNetworkPolicyDoesNotWaitForListenerRejectedBeforeRegistration(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	base := newADSCache(logger)
	cache := &blockingNetworkPolicyADSCache{Cache: base, upsertStarted: make(chan struct{}), continueUpsert: make(chan struct{})}
	_, restorer := promise.New[endpointstate.Restorer]()
	server := newTestADSServerWithCache(t, cache, logger, nil, newLocalEndpointStore(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), restorer)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Unlike programmatic redirect listeners, CEC listeners opt into NACK
	// recovery. Seed one during restoration so its first response can reject it.
	resources := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"npds-listener": server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false),
	}}
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), resources))
	listenerResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	listenerDelivery := deliverADSResponse(t, cache, 1, listenerResponse)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	type updateResult struct {
		err      error
		rollback revert.Revertible
	}
	result := make(chan updateResult, 1)
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	go func() {
		err, rollback := server.UpdateNetworkPolicy(ctx, ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
		result <- updateResult{err: err, rollback: rollback}
	}()
	select {
	case <-cache.upsertStarted:
	case <-time.After(time.Second):
		t.Fatal("NetworkPolicy upsert did not reach the cache")
	}
	replyADSResponse(t, cache, 1, listenerResponse, listenerDelivery, "rejected NPDS listener")
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "npds-listener")
	close(cache.continueUpsert)
	select {
	case update := <-result:
		require.NoError(t, update.err)
		require.NotNil(t, update.rollback)
		update.rollback.Finalize()
	case <-time.After(time.Second):
		t.Fatal("NetworkPolicy update did not complete")
	}
	require.NoError(t, wg.Wait())
}

func TestUpdateNetworkPolicyNoOpWaitsForCurrentACK(t *testing.T) {
	server, cache := newADSServerFixture(t)
	require.NoError(t, server.AddListener(t.Context(), "npds-listener", policy.ParserTypeHTTP, 12345, false, false, nil))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	firstWG := completion.NewWaitGroup(ctx)
	err, rollback := server.UpdateNetworkPolicy(ctx, ep, epp, firstWG)
	require.NoError(t, err)
	require.NotNil(t, rollback)
	defer rollback.Finalize()
	firstDone := waitForADSCompletion(t, firstWG)
	response := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, "")
	// An unrelated server update must not move this policy's no-op wait to a later response.
	require.NoError(t, server.AddListener(ctx, "intervening-listener", policy.ParserTypeHTTP, 12346, false, false, nil))
	secondWG := completion.NewWaitGroup(ctx)
	err, noOpRollback := server.UpdateNetworkPolicy(ctx, ep, epp, secondWG)
	require.NoError(t, err)
	require.NotNil(t, noOpRollback)
	noOpRollback.Finalize()
	secondDone := waitForADSCompletion(t, secondWG)
	requireADSCompletionPending(t, firstDone)
	requireADSCompletionPending(t, secondDone)
	delivered := deliverADSResponse(t, cache, 1, response)
	replyADSResponse(t, cache, 1, response, delivered, "")
	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
}

func TestUpdateNetworkPolicyPreservesOtherServerResources(t *testing.T) {
	resources := adsDefaultResources()
	server, cache := newSeededADSServerFixture(t, resources)
	oldPolicy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 1, ipv4: "192.0.2.1"})
	newPolicy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"})
	require.False(t, proto.Equal(oldPolicy, newPolicy))
	require.True(t, proto.Equal(resources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))
}

func TestNPDSListenerChangesKeepWaitsUntilLastListenerDisappears(t *testing.T) {
	_, restorer := promise.New[endpointstate.Restorer]()
	server, cache := newADSServerFixture(t, restorer)
	resources := xds.NewResources()
	for i := range 2 {
		name := fmt.Sprintf("npds-listener-%d", i+1)
		resources.Listeners[name] = server.getListenerConf(name, policy.ParserTypeHTTP, uint16(12345+i), false, false)
	}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources))
	server.markRestoreCompleted()
	wg := completion.NewWaitGroup(t.Context())
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
	require.NoError(t, err)
	require.NotNil(t, rollback)
	defer rollback.Finalize()
	done := waitForADSCompletion(t, wg)
	first := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"npds-listener-1": resources.Listeners["npds-listener-1"]}}
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), first))
	requireADSCompletionPending(t, done)
	second := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"npds-listener-2": resources.Listeners["npds-listener-2"]}}
	replacement := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"npds-listener-3": server.getListenerConf("npds-listener-3", policy.ParserTypeHTTP, 12347, false, false),
	}}
	updated := startADSResourceUpdate(server, t.Context(), second, replacement)
	require.Eventually(t, func() bool {
		return cache.GetResource(localNodeID, typeurl.Listener, "npds-listener-3") != nil
	}, time.Second, time.Millisecond)
	ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	require.NoError(t, <-updated)
	requireADSCompletionPending(t, done)
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), replacement))
	require.NoError(t, <-done)
	for i := range 3 {
		requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, fmt.Sprintf("npds-listener-%d", i+1))
	}
}

func TestRemoveNetworkPolicy(t *testing.T) {
	for _, addresses := range []struct {
		name    string
		ipv4    string
		ipv6    string
		changed bool
	}{
		{name: "ipv4", ipv4: "10.0.0.1"},
		{name: "ipv6", ipv6: "2001:db8::1"},
		{name: "changed-address", ipv4: "10.0.0.1", changed: true},
	} {
		for _, count := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/count=%d", addresses.name, count), func(t *testing.T) {
				resources := adsDefaultResources()
				server, cache := newSeededADSServerFixture(t, resources)
				endpoints := []*testableEndpointUpdater{{id: 40, ipv4: addresses.ipv4, ipv6: addresses.ipv6}, {id: 1, ipv4: "127.0.0.1"}}
				for _, ep := range endpoints[:count] {
					seedADSNetworkPolicy(t, server, ep)
				}
				for i, ep := range endpoints {
					name := strconv.FormatUint(ep.id, 10)
					if i < count {
						require.Equal(t, ep.id, cachedNetworkPolicy(t, cache, localNodeID, name).GetEndpointId())
					} else {
						requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, name)
					}
				}
				for i, ep := range endpoints[:count] {
					previousNames := ep.GetPolicyNames()
					if addresses.changed && i == 0 {
						ep.ipv4 = "10.0.0.9"
					}
					server.RemoveNetworkPolicy(t.Context(), ep)
					for j, candidate := range endpoints {
						name := strconv.FormatUint(candidate.id, 10)
						if j > i && j < count {
							require.Equal(t, candidate.id, cachedNetworkPolicy(t, cache, localNodeID, name).GetEndpointId())
						} else {
							requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, name)
						}
					}
					for _, name := range previousNames {
						require.Nil(t, server.localEndpointStore.getLocalEndpoint(name))
					}
				}
				require.True(t, proto.Equal(resources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))
			})
		}
	}
}

func TestStartAdsGRPCServerRestoration(t *testing.T) {
	for _, tc := range []struct {
		name                string
		promise             bool
		restoreErr          error
		cancelBeforeResolve bool
	}{
		{name: "restored", promise: true},
		{name: "restore-deadline", promise: true, restoreErr: context.DeadlineExceeded},
		{name: "restore-canceled", promise: true, restoreErr: context.Canceled},
		{name: "no-restorer"},
		{name: "context-canceled-before-resolve", promise: true, cancelBeforeResolve: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, restorer := promise.New[endpointstate.Restorer]()
			if !tc.promise {
				restorer = nil
			}
			server, _ := newADSServerFixture(t, restorer)
			server.config.policyRestoreTimeout = 5 * time.Second
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- server.startAdsGRPCServer(ctx) }()
			if tc.cancelBeforeResolve {
				cancel()
			} else if tc.promise {
				resolver.Resolve(&mockRestorer{waitErr: tc.restoreErr})
			}
			if tc.cancelBeforeResolve || errors.Is(tc.restoreErr, context.Canceled) {
				require.ErrorIs(t, <-done, context.Canceled)
				return
			}
			// WaitForReady tolerates dialing before socket creation, bounded by ctx.
			// The response then proves the server is serving without reading stopFunc
			// concurrently with its initialization.
			client := newUnixADSClient(t, server.socketPath)
			stream, err := client.StreamAggregatedResources(ctx, grpc.WaitForReady(true))
			require.NoError(t, err)
			require.NoError(t, stream.Send(&envoy_service_discovery.DiscoveryRequest{
				Node: &envoy_config_core_v3.Node{Id: localNodeID}, TypeUrl: ListenerTypeURL,
			}))
			response, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, ListenerTypeURL, response.TypeUrl)
			require.Empty(t, response.Resources)
			cancel()
			require.NoError(t, <-done)
			require.NotNil(t, server.stopFunc)
			server.stopFunc()
		})
	}
}
