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
	server, cache := newADSServerFixture(t)
	first := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener-1": {Name: "listener-1"},
	}}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), first, nil))
	accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	second := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener-2": {Name: "listener-2"},
	}}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), second, nil))
	response := createADSWatchResponse(t, cache, ListenerTypeURL, accepted)
	delivered := deliverADSResponse(t, cache, 1, response)

	for _, resources := range []xds.Resources{first, second} {
		wg := completion.NewWaitGroup(t.Context())
		require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, wg))
		done := waitForADSCompletion(t, wg)
		if resources.Listeners["listener-1"] == nil {
			requireADSCompletionPending(t, done)
			replyADSResponse(t, cache, 1, response, delivered, "")
		}
		require.NoError(t, <-done)
	}
}

func TestUpdateEnvoyResourcesNoOpListenerWaitsForCurrentACK(t *testing.T) {
	server, cache := newADSServerFixture(t)
	resources := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"listener": {Name: "listener"},
	}}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.Resources{}, resources, nil))
	response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	delivered := deliverADSResponse(t, cache, 1, response)
	wg := completion.NewWaitGroup(t.Context())
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), resources, resources, wg))
	done := waitForADSCompletion(t, wg)
	requireADSCompletionPending(t, done)
	replyADSResponse(t, cache, 1, response, delivered, "")
	require.NoError(t, <-done)
}

func TestADSResponseNACKRevertsServerUpdate(t *testing.T) {
	server, cache := newADSServerFixture(t)
	resources := adsTestResources(adsTestListener(80))
	resources.Secrets["related"] = &envoy_config_tls.Secret{Name: "related"}
	wg := completion.NewWaitGroup(t.Context())
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, wg))
	done := waitForADSCompletion(t, wg)
	unrelated := xds.NewResources()
	unrelated.Secrets["unrelated"] = &envoy_config_tls.Secret{Name: "unrelated"}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), unrelated, nil))
	requireADSCompletionPending(t, done)
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, "", "rejected listener")
	require.ErrorContains(t, <-done, "rejected listener")
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "related")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "unrelated")

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

func TestRemoveListenerNACKRestoresResponseState(t *testing.T) {
	server, cache := newADSServerFixture(t)
	require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil))
	accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	server.RemoveListener(t.Context(), "test-listener", nil)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")
	// RemoveListener exposes no caller rollback, but its removal can still be
	// rejected by Envoy. Recovery must not recreate a server-owned reference.
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, accepted, "rejected listener removal")
	require.NotNil(t, cachedListener(t, cache, localNodeID, "test-listener"))
	// Re-acquiring and releasing one reference must delete the recovered
	// resource again. A reference resurrected by the NACK would leave it live.
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
	server, cache := newADSServerFixture(t)
	old := adsDefaultResources()
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), old, nil))
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
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), old, next, nil))
	requireCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig2")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	require.Same(t, policy, cachedNetworkPolicy(t, cache, localNodeID, "40"), "Envoy resource updates must not mutate NPDS")
}

func TestADSListenersRequiringRecreate(t *testing.T) {
	oldListener := adsTestListener(80, 8443)
	newListener := adsTestListener(80, 8444)
	require.Equal(t, []string{"listener1"}, adsListenersRequiringRecreate(
		map[string]*envoy_config_listener.Listener{"listener1": oldListener},
		map[string]*envoy_config_listener.Listener{"listener1": newListener},
	))

	oldListener.EnableReusePort = wrapperspb.Bool(true)
	newListener.EnableReusePort = wrapperspb.Bool(true)
	require.Empty(t, adsListenersRequiringRecreate(
		map[string]*envoy_config_listener.Listener{"listener1": oldListener},
		map[string]*envoy_config_listener.Listener{"listener1": newListener},
	))
}

func TestUpdateEnvoyResourcesRecreatesListenerAfterAddressChange(t *testing.T) {
	addressChanges := []struct {
		name        string
		oldListener *envoy_config_listener.Listener
		newListener *envoy_config_listener.Listener
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
	}

	for _, addressChange := range addressChanges {
		t.Run(addressChange.name, func(t *testing.T) {
			server, cache := newADSServerFixture(t)

			oldResources := adsTestResources(addressChange.oldListener)
			require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), oldResources, nil))

			newResources := adsTestResources(addressChange.newListener)

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
			}()

			require.Eventually(t, func() bool {
				return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil
			}, time.Second, 10*time.Millisecond)
			deleteVersion := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")

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
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(81, 8444))
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)

	require.NoError(t, server.UpdateEnvoyResources(t.Context(), oldResources, newResources, wg))
	require.True(t, proto.Equal(newResources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))

	ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	require.NoError(t, wg.Wait())

}

func TestUpdateEnvoyResourcesAddressChangePreservesNewerListenerOnDelayedNACK(t *testing.T) {
	server, cache := newADSServerFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	initial := adsTestResources(adsTestListener(80, 8442))
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), initial, nil))
	accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
	tracked := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), tracked, nil))
	oldResponse := createADSWatchResponse(t, cache, ListenerTypeURL, accepted)
	oldDelivery := deliverADSResponse(t, cache, 1, oldResponse)

	desired := adsTestResources(adsTestListener(80, 8444))
	result := make(chan error, 1)
	go func() { result <- server.UpdateEnvoyResources(ctx, tracked, desired, nil) }()
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

func TestUpdateEnvoyResourcesRestoresListenerAfterAddressChangeFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement bool
		rejection   string
		canceled    bool
	}{
		{name: "deletion-nack", rejection: "rejected listener deletion"},
		{name: "deletion-timeout"},
		{name: "replacement-canceled", replacement: true, canceled: true},
		{name: "replacement-nack", replacement: true, rejection: "rejected listener"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cache := newADSServerFixture(t)
			old := adsTestResources(adsTestListener(80, 8443))
			require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), old, nil))
			accepted := ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			next := adsTestResources(adsTestListener(80, 8444))
			timeout := 5 * time.Second
			if tc.name == "deletion-timeout" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- server.UpdateEnvoyResources(ctx, old, next, nil) }()
			if tc.name != "deletion-timeout" {
				require.Eventually(t, func() bool { return cache.GetResource(localNodeID, typeurl.Listener, "listener1") == nil }, time.Second, time.Millisecond)
				if tc.replacement {
					accepted = ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, accepted)
					require.Eventually(t, func() bool { return cache.GetResource(localNodeID, typeurl.Listener, "listener1") != nil }, time.Second, time.Millisecond)
				}
				if tc.canceled {
					cancel()
				} else {
					response := createADSWatchResponse(t, cache, ListenerTypeURL, accepted)
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
				}
			}
			select {
			case err := <-result:
				switch {
				case tc.canceled:
					require.ErrorIs(t, err, context.Canceled)
				case tc.rejection != "":
					require.ErrorContains(t, err, tc.rejection)
				default:
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			case <-time.After(time.Second):
				t.Fatal("listener address update did not finish")
			}
			require.True(t, proto.Equal(old.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))
		})
	}
}

func TestUpdateEnvoyResourcesRetriesReplacementBindFailure(t *testing.T) {
	server, cache := newADSServerFixture(t)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
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
		{name: "removals-only", baseline: "unacked-resources", noListeners: true, wait: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cache := newADSServerFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			old := xds.NewResources()
			if tc.baseline == "accepted-listener" {
				old.Listeners["listener1"] = adsDefaultResources().Listeners["listener1"]
				require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), old, nil))
				ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
			} else if tc.baseline == "unacked-resources" {
				old = adsDefaultResources()
				require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), old, nil))
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
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			require.NoError(t, server.UpdateEnvoyResources(ctx, old, next, wg))
			done := waitForADSCompletion(t, wg)
			if tc.wait {
				requireADSCompletionPending(t, done)
				if tc.cluster {
					ackADSResourceVersionFrom(t, cache, 1, ClusterTypeURL, "")
					if tc.baseline != "accepted-listener" {
						requireADSCompletionPending(t, done)
					}
					// RDS remains unacknowledged: it is not a caller-wait dependency.
					deliverADSResponse(t, cache, 1, createADSWatchResponse(t, cache, RouteTypeURL, ""))
				}
				ackADSResourceVersionFrom(t, cache, 1, ListenerTypeURL, "")
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
	server, cache := newADSServerFixture(t)
	ctx := context.Background()

	xdsResources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{},
		Clusters:  map[string]*envoy_config_cluster.Cluster{},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{},
		Secrets:   map[string]*envoy_config_tls.Secret{},
	}

	// Deleting empty resources should be no-op.
	err := server.DeleteEnvoyResources(ctx, xdsResources, nil)
	assert.NoError(t, err)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireNoCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireNoCachedResource(t, cache, localNodeID, NetworkPolicyTypeURL, "40")
	requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")

	// Add some resources and then delete them.
	err = server.UpdateEnvoyResources(ctx, xds.NewResources(), adsDefaultResources(), nil)
	assert.NoError(t, err)
	policy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 40, ipv4: "10.0.0.1"})

	requireCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
	require.Same(t, policy, cachedNetworkPolicy(t, cache, localNodeID, "40"))

	err = server.DeleteEnvoyResources(ctx, adsDefaultResources(), nil)
	assert.NoError(t, err)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener1")
	requireNoCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	require.Same(t, policy, cachedNetworkPolicy(t, cache, localNodeID, "40"), "Envoy resource deletion must not mutate NPDS")
	requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireNoCachedResource(t, cache, localNodeID, EndpointTypeURL, "cluster1")
}

func TestUpdateNetworkPolicy(t *testing.T) {
	server, cache := newADSServerFixture(t)
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), adsDefaultResources(), nil))
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
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, nil))

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
	require.Nil(t, revertible)

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
			server, cache := newADSServerFixture(t)
			require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), adsDefaultResources(), nil))
			var resources xds.Resources
			if action != "never-added" {
				resources = xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
					"npds-listener": server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false),
				}}
				if action == "bulk-delete" {
					require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, nil))
				} else {
					require.NoError(t, server.AddListener(t.Context(), "npds-listener", policy.ParserTypeHTTP, 12345, false, false, nil))
				}
			}
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
				require.NoError(t, server.DeleteEnvoyResources(t.Context(), resources, nil))
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
	server, cache := newADSServerFixture(t)
	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, nil))
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
	require.NoError(t, err)
	require.NotNil(t, rollback)
	response := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, "")
	delivered := deliverADSResponse(t, cache, 1, response)
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), resources, nil))
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
	server := newTestADSServerWithCache(t, cache, logger, nil, newLocalEndpointStore(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NoError(t, server.AddListener(ctx, "npds-listener", policy.ParserTypeHTTP, 12345, false, false, nil))
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
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "listener")
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
	require.Nil(t, noOpRollback)
	secondDone := waitForADSCompletion(t, secondWG)
	requireADSCompletionPending(t, firstDone)
	requireADSCompletionPending(t, secondDone)
	delivered := deliverADSResponse(t, cache, 1, response)
	replyADSResponse(t, cache, 1, response, delivered, "")
	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
}

func TestUpdateNetworkPolicyPreservesOtherServerResources(t *testing.T) {
	server, cache := newADSServerFixture(t)
	resources := adsDefaultResources()
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, nil))
	oldPolicy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 1, ipv4: "192.0.2.1"})
	newPolicy := seedADSNetworkPolicy(t, server, &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"})
	require.False(t, proto.Equal(oldPolicy, newPolicy))
	require.True(t, proto.Equal(resources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1")))
}

func TestNPDSListenerChangesKeepWaitsUntilLastListenerDisappears(t *testing.T) {
	server, cache := newADSServerFixture(t)
	resources := xds.NewResources()
	for i := range 2 {
		name := fmt.Sprintf("npds-listener-%d", i+1)
		resources.Listeners[name] = server.getListenerConf(name, policy.ParserTypeHTTP, uint16(12345+i), false, false)
	}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, nil))
	wg := completion.NewWaitGroup(t.Context())
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	err, rollback := server.UpdateNetworkPolicy(t.Context(), ep, policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()), wg)
	require.NoError(t, err)
	require.NotNil(t, rollback)
	defer rollback.Finalize()
	done := waitForADSCompletion(t, wg)
	first := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"npds-listener-1": resources.Listeners["npds-listener-1"]}}
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), first, nil))
	requireADSCompletionPending(t, done)
	second := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"npds-listener-2": resources.Listeners["npds-listener-2"]}}
	replacement := xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
		"npds-listener-3": server.getListenerConf("npds-listener-3", policy.ParserTypeHTTP, 12347, false, false),
	}}
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), second, replacement, nil))
	requireADSCompletionPending(t, done)
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), replacement, nil))
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
				server, cache := newADSServerFixture(t)
				resources := adsDefaultResources()
				require.NoError(t, server.UpdateEnvoyResources(t.Context(), xds.NewResources(), resources, nil))
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
