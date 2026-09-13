// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	xds_cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_stream "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
)

func GetLocalEndpointStoreForTest() *LocalEndpointStore {
	return &LocalEndpointStore{
		networkPolicyEndpoints: make(map[string]endpoint.EndpointUpdater),
	}
}

var (
	DEFAULT_CLA = envoy_config_endpoint.ClusterLoadAssignment{
		ClusterName: "cluster1",
		Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{
			{
				Locality: &envoy_config_core_v3.Locality{
					Region:  "us-west",
					Zone:    "us-west-1",
					SubZone: "us-west-1a",
				},
			},
		},
	}

	DEFAULT_RESOURCES = xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener1": {
				Name: "listener1",
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 8080,
							},
						},
					},
				},
				FilterChains: []*envoy_config_listener.FilterChain{{
					Filters: []*envoy_config_listener.Filter{{
						Name: "envoy.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
								StatPrefix: "http_proxy",
								RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
									Rds: &envoy_config_http.Rds{
										RouteConfigName: "routeConfig1",
									},
								},
							}),
						},
					}},
				}},
			},
		},
		Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster1": {
				Name:           "cluster1",
				LoadAssignment: &DEFAULT_CLA,
				ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
					Type: *envoy_config_cluster.Cluster_EDS.Enum(),
				},
			},
		},
		Secrets: map[string]*envoy_config_tls.Secret{
			"secret1": {
				Name: "secret1",
			},
		},
		Routes: map[string]*envoy_config_route.RouteConfiguration{
			"routeConfig1": {
				Name: "routeConfig1",
			},
		},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{
			"endpoint1": &DEFAULT_CLA,
		},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"40": {
				EndpointId:  40,
				EndpointIps: []string{"10.0.0.1"},
			},
		},
	}
)

func adsTestListener(primaryPort uint32, additionalPorts ...uint32) *envoy_config_listener.Listener {
	ports := append([]uint32{primaryPort}, additionalPorts...)
	listener := testListenerWithPorts(ports...)
	listener.Name = "listener1"
	listener.EnableReusePort = wrapperspb.Bool(false)
	listener.FilterChains = []*envoy_config_listener.FilterChain{{
		Filters: []*envoy_config_listener.Filter{{
			Name: "envoy.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{
				TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
					StatPrefix: "http_proxy",
					RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
						Rds: &envoy_config_http.Rds{RouteConfigName: "routeConfig1"},
					},
				}),
			},
		}},
	}}
	return listener
}

func adsTestResources(listener *envoy_config_listener.Listener) xds.Resources {
	resources := xds.NewResources()
	resources.Listeners[listener.GetName()] = listener
	resources.Routes["routeConfig1"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig1"}
	return resources
}

func ackADSResourceVersion(t *testing.T, cache xdsnew.Cache, streamID int64, typeURL string) string {
	t.Helper()
	acceptedVersion := ""
	if snapshot, err := cache.GetSnapshot(localNodeID); err == nil {
		acceptedVersion = snapshot.GetVersion(typeURL)
	}
	watchResponse := createADSWatchResponse(t, cache, typeURL, acceptedVersion)
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	version := snapshot.GetVersion(typeURL)
	require.NotEmpty(t, version)

	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     typeURL,
		VersionInfo: version,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(watchResponse.GetContext(), streamID, watchResponse.GetRequest(), resp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(streamID, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: version,
	}))
	return version
}

func nackADSResourceVersion(t *testing.T, cache xdsnew.Cache, streamID int64, typeURL, acceptedVersion, message string) {
	t.Helper()
	watchResponse := createADSWatchResponse(t, cache, typeURL, acceptedVersion)
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	rejectedVersion := snapshot.GetVersion(typeURL)
	require.NotEmpty(t, rejectedVersion)
	require.NotEqual(t, acceptedVersion, rejectedVersion)

	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     typeURL,
		VersionInfo: rejectedVersion,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(watchResponse.GetContext(), streamID, watchResponse.GetRequest(), resp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(streamID, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: acceptedVersion,
		ErrorDetail: &status.Status{Message: message},
	}))
}

type countingADSCache struct {
	xdsnew.Cache
	generated atomic.Uint64
	published atomic.Uint64
}

type revertCapturingADSCache struct {
	xdsnew.Cache
	revertFuncs []xdsnew.RevertFunc
}

type blockingNetworkPolicyADSCache struct {
	xdsnew.Cache
	upsertStarted  chan struct{}
	continueUpsert chan struct{}
}

func (c *blockingNetworkPolicyADSCache) UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	close(c.upsertStarted)
	select {
	case <-c.continueUpsert:
	case <-ctx.Done():
		return false, nil, nil, ctx.Err()
	}
	return c.Cache.UpsertNetworkPolicy(ctx, nodeID, name, resource, wg, callback)
}

func (c *revertCapturingADSCache) ApplyResources(ctx context.Context, nodeID string, mutations xdsnew.ResourceMutations, wg *completion.WaitGroup, typeURLs xdsnew.TypeURLCallbacks) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.ApplyResources(ctx, nodeID, mutations, wg, typeURLs))
}

func (c *revertCapturingADSCache) captureRevert(updated bool, revertFunc xdsnew.RevertFunc, finalizeFunc xdsnew.FinalizeFunc, err error) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	if updated && revertFunc != nil {
		c.revertFuncs = append(c.revertFuncs, revertFunc)
		// Keep the caller-owned revert live for tests which exercise it
		// directly. Production callers invoke the returned finalizer.
		finalizeFunc = func() {}
	}
	return updated, revertFunc, finalizeFunc, err
}

func (c *revertCapturingADSCache) UpsertListener(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.UpsertListener(ctx, nodeID, name, resource, wg, callback))
}

func (c *revertCapturingADSCache) RemoveListener(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.RemoveListener(ctx, nodeID, name, wg, callback))
}

func (c *revertCapturingADSCache) UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.UpsertNetworkPolicy(ctx, nodeID, name, resource, wg, callback))
}

func (c *revertCapturingADSCache) RemoveNetworkPolicy(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.RemoveNetworkPolicy(ctx, nodeID, name, wg, callback))
}

func (c *revertCapturingADSCache) UpsertNetworkPolicyHosts(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.UpsertNetworkPolicyHosts(ctx, nodeID, name, resource))
}

func (c *revertCapturingADSCache) RemoveNetworkPolicyHosts(ctx context.Context, nodeID, name string) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.captureRevert(c.Cache.RemoveNetworkPolicyHosts(ctx, nodeID, name))
}

func (c *countingADSCache) ApplyResources(ctx context.Context, nodeID string, mutations xdsnew.ResourceMutations, wg *completion.WaitGroup, typeURLs xdsnew.TypeURLCallbacks) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.ApplyResources(ctx, nodeID, mutations, wg, typeURLs))
}

func (c *countingADSCache) countUpdate(updated bool, revertFunc xdsnew.RevertFunc, finalizeFunc xdsnew.FinalizeFunc, err error) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	if updated {
		c.generated.Add(1)
		c.published.Add(1)
	}
	return updated, revertFunc, finalizeFunc, err
}

func (c *countingADSCache) UpsertListener(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.UpsertListener(ctx, nodeID, name, resource, wg, callback))
}

func (c *countingADSCache) RemoveListener(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.RemoveListener(ctx, nodeID, name, wg, callback))
}

func (c *countingADSCache) UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.UpsertNetworkPolicy(ctx, nodeID, name, resource, wg, callback))
}

func (c *countingADSCache) RemoveNetworkPolicy(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.RemoveNetworkPolicy(ctx, nodeID, name, wg, callback))
}

func (c *countingADSCache) UpsertNetworkPolicyHosts(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.UpsertNetworkPolicyHosts(ctx, nodeID, name, resource))
}

func (c *countingADSCache) RemoveNetworkPolicyHosts(ctx context.Context, nodeID, name string) (bool, xdsnew.RevertFunc, xdsnew.FinalizeFunc, error) {
	return c.countUpdate(c.Cache.RemoveNetworkPolicyHosts(ctx, nodeID, name))
}

func (c *countingADSCache) reset() {
	c.generated.Store(0)
	c.published.Store(0)
}

func createADSWatchResponse(t *testing.T, cache xdsnew.Cache, typeURL, version string) xds_cache.Response {
	t.Helper()
	request := &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     typeURL,
		VersionInfo: version,
	}
	responses := make(chan xds_cache.Response, 1)
	cancel, err := cache.CreateWatch(request, envoy_stream.NewSotwSubscription(nil, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case response := <-responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ADS watch response")
		return nil
	}
}

func TestSnapshotRevertGeneration(t *testing.T) {
	newServer := func(t *testing.T) (*adsServer, *revertCapturingADSCache) {
		t.Helper()
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		cache := &revertCapturingADSCache{Cache: xdsnew.NewCache(logger, false)}
		return newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil), cache
	}
	resources := func(endpointID uint64) xds.Resources {
		resources := xds.NewResources()
		resources.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: endpointID}
		return resources
	}

	t.Run("current generation is reverted", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(1), nil))
		cache.revertFuncs = nil

		wg := completion.NewWaitGroup(ctx)
		t.Cleanup(wg.Cancel)
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(2), wg))
		require.Len(t, cache.revertFuncs, 1)

		_, reverted := cache.revertFuncs[0](revertCurrentGeneration)
		require.True(t, reverted)
		current := cachedNetworkPolicy(t, cache, localNodeID, "policy")
		require.Equal(t, uint64(1), current.EndpointId)
	})

	t.Run("updates share a global generation space without coupling node reverts", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		publish := func(nodeID string, endpointID uint64) {
			next := resources(endpointID)
			server.mutex.Lock()
			err := func() error {
				removed := xds.Resources{NetworkPolicies: cachedNetworkPolicies(cache, nodeID)}
				_, err := server.applyResourceUpdate(ctx, nodeID, xdsnew.ResourceMutations{Removed: removed, Upserted: next}, nil, xdsnew.TypeURLCallbacks{})
				return err
			}()
			server.mutex.Unlock()
			require.NoError(t, err)
		}

		publish("node-a", 1) // generation 1
		publish("node-b", 1) // generation 2
		cache.revertFuncs = nil
		publish("node-a", 2) // generation 3
		require.Len(t, cache.revertFuncs, 1)
		revertNodeA := cache.revertFuncs[0]
		publish("node-b", 2) // generation 4

		// The global allocator advanced for node-b, but node-a still has the
		// exact resource generation expected by its revert.
		generation, reverted := revertNodeA(revertCurrentGeneration)
		require.True(t, reverted)
		require.Equal(t, uint64(5), generation)
		require.Equal(t, uint64(1), cachedNetworkPolicy(t, cache, "node-a", "policy").EndpointId)
		require.Equal(t, uint64(2), cachedNetworkPolicy(t, cache, "node-b", "policy").EndpointId)
	})

	t.Run("superseded ABA generation is not reverted", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(1), nil))
		cache.revertFuncs = nil

		wg := completion.NewWaitGroup(ctx)
		t.Cleanup(wg.Cancel)
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(2), wg))
		require.Len(t, cache.revertFuncs, 1)
		staleRevert := cache.revertFuncs[0]

		// Return to the same resource contents through a later generation. A
		// content hash cannot distinguish this state from the one associated
		// with staleRevert, but its generation token can.
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(3), nil))
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(2), nil))
		beforeRevert := cachedNetworkPolicy(t, cache, localNodeID, "policy")

		_, reverted := staleRevert(2)
		require.False(t, reverted)
		require.Same(t, beforeRevert, cachedNetworkPolicy(t, cache, localNodeID, "policy"))
		require.Equal(t, uint64(2), beforeRevert.EndpointId)
	})

	t.Run("coalesced generations revert to the last accepted state", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(1), nil))
		cache.revertFuncs = nil

		wg2 := completion.NewWaitGroup(ctx)
		t.Cleanup(wg2.Cancel)
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(2), wg2))
		wg3 := completion.NewWaitGroup(ctx)
		t.Cleanup(wg3.Cancel)
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(3), wg3))
		require.Len(t, cache.revertFuncs, 2)

		expectedGeneration := revertCurrentGeneration
		for _, revertFunc := range slices.Backward(cache.revertFuncs) {
			var reverted bool
			expectedGeneration, reverted = revertFunc(expectedGeneration)
			require.True(t, reverted)
		}

		current := cachedNetworkPolicy(t, cache, localNodeID, "policy")
		require.Equal(t, uint64(1), current.EndpointId)
	})

	t.Run("replayed revert lets a NACK continue through coalesced generations", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(1), nil))
		cache.revertFuncs = nil

		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(2), nil))
		require.NoError(t, server.UpsertEnvoyResources(ctx, resources(3), nil))
		require.Len(t, cache.revertFuncs, 2)
		olderRevert, newerRevert := cache.revertFuncs[0], cache.revertFuncs[1]

		const responseGeneration = uint64(3)
		revertedGeneration, reverted := newerRevert(revertCurrentGeneration)
		require.True(t, reverted)
		require.Equal(t, uint64(2), cachedNetworkPolicy(t, cache, localNodeID, "policy").EndpointId)

		// Endpoint regeneration already applied this inverse. A subsequent NACK
		// observes that there is nothing left for this function to restore; the
		// completion callback must nevertheless continue through older updates.
		replayedGeneration, reverted := newerRevert(responseGeneration)
		require.False(t, reverted)
		require.Equal(t, revertedGeneration, replayedGeneration)

		_, reverted = olderRevert(replayedGeneration)
		require.True(t, reverted)
		require.Equal(t, uint64(1), cachedNetworkPolicy(t, cache, localNodeID, "policy").EndpointId)
	})

	t.Run("cache-owned listener revert is reflected in NPDS state", func(t *testing.T) {
		server, cache := newServer(t)
		listener := server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
		resources := xds.NewResources()
		resources.Listeners[listener.Name] = listener
		require.NoError(t, server.UpsertEnvoyResources(t.Context(), resources, nil))
		require.True(t, server.hasNPDSListeners())
		require.Len(t, cache.revertFuncs, 1)

		_, reverted := cache.revertFuncs[0](revertCurrentGeneration)
		require.True(t, reverted)
		require.False(t, server.hasNPDSListeners())
	})

	t.Run("NACK reverts a coalesced untracked generation", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		listenerResources := func(name string) xds.Resources {
			resources := xds.NewResources()
			resources.Listeners[name] = &envoy_config_listener.Listener{Name: name}
			return resources
		}
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-1"), nil))

		baselineResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
		baselineSnapshot, err := cache.GetSnapshot(localNodeID)
		require.NoError(t, err)
		baselineVersion := baselineSnapshot.GetVersion(ListenerTypeURL)
		node := &envoy_config_core_v3.Node{Id: localNodeID}
		cache.GetCompletionCallbacks().OnStreamResponse(
			baselineResponse.GetContext(), 1, baselineResponse.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: baselineVersion,
				TypeUrl:     ListenerTypeURL,
				Nonce:       "baseline",
			})
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       ListenerTypeURL,
			VersionInfo:   baselineVersion,
			ResponseNonce: "baseline",
		}))

		wg := completion.NewWaitGroup(ctx)
		t.Cleanup(wg.Cancel)
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-2"), wg))
		// Generation 3 has no WaitGroup, matching the tracked/untracked update
		// shape produced by the synthetic ingress policy in #43519.
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-3"), nil))

		response := createADSWatchResponse(t, cache, ListenerTypeURL, baselineVersion)
		currentSnapshot, err := cache.GetSnapshot(localNodeID)
		require.NoError(t, err)
		currentVersion := currentSnapshot.GetVersion(ListenerTypeURL)
		cache.GetCompletionCallbacks().OnStreamResponse(
			response.GetContext(), 1,
			&envoy_service_discovery.DiscoveryRequest{Node: node, TypeUrl: ListenerTypeURL},
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: currentVersion,
				TypeUrl:     ListenerTypeURL,
				Nonce:       "nonce-3",
			})
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       ListenerTypeURL,
			VersionInfo:   baselineVersion,
			ResponseNonce: "nonce-3",
			ErrorDetail:   &status.Status{Message: "rejected coalesced listener"},
		}))

		require.ErrorContains(t, wg.Wait(), "rejected coalesced listener")
		current := cachedListeners(cache, localNodeID)
		require.Contains(t, current, "listener-1")
		require.NotContains(t, current, "listener-2")
		require.NotContains(t, current, "listener-3")
	})

	t.Run("NACK reverts an untracked generation staged before a tracked generation", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		listenerResources := func(name string) xds.Resources {
			resources := xds.NewResources()
			resources.Listeners[name] = &envoy_config_listener.Listener{Name: name}
			return resources
		}
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-1"), nil))

		baselineResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
		baselineSnapshot, err := cache.GetSnapshot(localNodeID)
		require.NoError(t, err)
		baselineVersion := baselineSnapshot.GetVersion(ListenerTypeURL)
		node := &envoy_config_core_v3.Node{Id: localNodeID}
		cache.GetCompletionCallbacks().OnStreamResponse(
			baselineResponse.GetContext(), 1, baselineResponse.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: baselineVersion,
				TypeUrl:     ListenerTypeURL,
				Nonce:       "baseline",
			})
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       ListenerTypeURL,
			VersionInfo:   baselineVersion,
			ResponseNonce: "baseline",
		}))

		// Lazy finalization allows an untracked mutation to be staged before a
		// later tracked one. Both enter the same response and must therefore be
		// rolled back together if Envoy rejects it.
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-2"), nil))
		wg := completion.NewWaitGroup(ctx)
		t.Cleanup(wg.Cancel)
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-3"), wg))

		response := createADSWatchResponse(t, cache, ListenerTypeURL, baselineVersion)
		currentSnapshot, err := cache.GetSnapshot(localNodeID)
		require.NoError(t, err)
		currentVersion := currentSnapshot.GetVersion(ListenerTypeURL)
		cache.GetCompletionCallbacks().OnStreamResponse(
			response.GetContext(), 1,
			&envoy_service_discovery.DiscoveryRequest{Node: node, TypeUrl: ListenerTypeURL},
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: currentVersion,
				TypeUrl:     ListenerTypeURL,
				Nonce:       "nonce-3",
			})
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       ListenerTypeURL,
			VersionInfo:   baselineVersion,
			ResponseNonce: "nonce-3",
			ErrorDetail:   &status.Status{Message: "rejected lazily coalesced listener"},
		}))

		require.ErrorContains(t, wg.Wait(), "rejected lazily coalesced listener")
		current := cachedListeners(cache, localNodeID)
		require.Contains(t, current, "listener-1")
		require.NotContains(t, current, "listener-2")
		require.NotContains(t, current, "listener-3")
	})

	t.Run("NACK preserves a newer version of the same resource", func(t *testing.T) {
		_, cache := newServer(t)
		ctx := t.Context()
		policies := func(values map[string]uint64) xdsnew.ResourceMutations {
			resources := make(map[string]*cilium.NetworkPolicy, len(values))
			for name, endpointID := range values {
				resources[name] = &cilium.NetworkPolicy{EndpointId: endpointID}
			}
			return xdsnew.ResourceMutations{Upserted: xds.Resources{NetworkPolicies: resources}}
		}
		apply := func(mutations xdsnew.ResourceMutations, wg *completion.WaitGroup, tracked bool) {
			t.Helper()
			var typeURLs xdsnew.TypeURLCallbacks
			if tracked {
				typeURLs.Set(typeurl.NetworkPolicy, nil)
			}
			updated, _, _, err := cache.ApplyResources(ctx, localNodeID, mutations, wg, typeURLs)
			require.NoError(t, err)
			require.True(t, updated)
		}

		apply(policies(map[string]uint64{"newer": 1, "unchanged": 1}), nil, false)
		node := &envoy_config_core_v3.Node{Id: localNodeID}
		initial := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, "")
		baselineSnapshot, err := cache.GetSnapshot(localNodeID)
		require.NoError(t, err)
		baselineVersion := baselineSnapshot.GetVersion(NetworkPolicyTypeURL)
		cache.GetCompletionCallbacks().OnStreamResponse(
			initial.GetContext(), 1, initial.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: baselineVersion,
				TypeUrl:     NetworkPolicyTypeURL,
				Nonce:       "nonce-1",
			})
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       NetworkPolicyTypeURL,
			VersionInfo:   baselineVersion,
			ResponseNonce: "nonce-1",
		}))

		wg := completion.NewWaitGroup(ctx)
		t.Cleanup(wg.Cancel)
		apply(policies(map[string]uint64{"newer": 2, "unchanged": 2}), wg, true)
		response := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, baselineVersion)
		rejectedSnapshot, err := cache.GetSnapshot(localNodeID)
		require.NoError(t, err)
		rejectedVersion := rejectedSnapshot.GetVersion(NetworkPolicyTypeURL)
		cache.GetCompletionCallbacks().OnStreamResponse(
			response.GetContext(), 1, response.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: rejectedVersion,
				TypeUrl:     NetworkPolicyTypeURL,
				Nonce:       "nonce-2",
			})

		// This update is staged after the response under test was sent. Its own
		// ACK/NACK will arrive with a later response.
		apply(policies(map[string]uint64{"newer": 3}), nil, false)
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       NetworkPolicyTypeURL,
			VersionInfo:   baselineVersion,
			ResponseNonce: "nonce-2",
			ErrorDetail:   &status.Status{Message: "rejected policy"},
		}))

		require.ErrorContains(t, wg.Wait(), "rejected policy")
		current := cachedNetworkPolicies(cache, localNodeID)
		require.Equal(t, uint64(3), current["newer"].EndpointId)
		require.Equal(t, uint64(1), current["unchanged"].EndpointId)
	})

	t.Run("first NACK reverts coalesced cold-start resources", func(t *testing.T) {
		server, cache := newServer(t)
		ctx := t.Context()
		listenerResources := func(name string) xds.Resources {
			resources := xds.NewResources()
			resources.Listeners[name] = &envoy_config_listener.Listener{Name: name}
			return resources
		}

		// Startup resources have no WaitGroup and are coalesced before Envoy
		// establishes its first watch.
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-1"), nil))
		require.NoError(t, server.UpsertEnvoyResources(ctx, listenerResources("listener-2"), nil))

		response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
		version := response.GetResponseVersion()
		node := &envoy_config_core_v3.Node{Id: localNodeID}
		cache.GetCompletionCallbacks().OnStreamResponse(
			response.GetContext(), 1, response.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: version,
				TypeUrl:     ListenerTypeURL,
				Nonce:       "cold-start",
			})
		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       ListenerTypeURL,
			ResponseNonce: "cold-start",
			ErrorDetail:   &status.Status{Message: "rejected cold-start listeners"},
		}))

		require.Empty(t, maps.Collect(cache.Listeners(localNodeID)))
	})

	t.Run("NACK reverts only the rejected resource type", func(t *testing.T) {
		server, cache := newServer(t)
		resources := xds.NewResources()
		resources.Secrets["secret"] = &envoy_config_tls.Secret{Name: "secret"}
		resources.NetworkPolicies["policy"] = &cilium.NetworkPolicy{EndpointId: 1}
		require.NoError(t, server.UpsertEnvoyResources(t.Context(), resources, nil))

		secretRequest := &envoy_service_discovery.DiscoveryRequest{
			Node:          &envoy_config_core_v3.Node{Id: localNodeID},
			TypeUrl:       SecretTypeURL,
			ResourceNames: []string{"secret"},
		}
		secretResponses := make(chan xds_cache.Response, 1)
		cancel, err := cache.CreateWatch(
			secretRequest,
			envoy_stream.NewSotwSubscription(secretRequest.GetResourceNames(), false),
			secretResponses)
		require.NoError(t, err)
		t.Cleanup(cancel)
		var secretResponse xds_cache.Response
		select {
		case secretResponse = <-secretResponses:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ADS secret watch response")
		}
		policyResponse := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, "")
		const secretNonce = "rejected-secret"
		cache.GetCompletionCallbacks().OnStreamResponse(
			secretResponse.GetContext(), 1, secretResponse.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: secretResponse.GetResponseVersion(),
				TypeUrl:     SecretTypeURL,
				Nonce:       secretNonce,
			})
		const policyNonce = "rejected-policy"
		cache.GetCompletionCallbacks().OnStreamResponse(
			policyResponse.GetContext(), 1, policyResponse.GetRequest(),
			&envoy_service_discovery.DiscoveryResponse{
				VersionInfo: policyResponse.GetResponseVersion(),
				TypeUrl:     NetworkPolicyTypeURL,
				Nonce:       policyNonce,
			})

		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          &envoy_config_core_v3.Node{Id: localNodeID},
			TypeUrl:       SecretTypeURL,
			ResponseNonce: secretNonce,
			ErrorDetail:   &status.Status{Message: "rejected secret"},
		}))
		_, secretExists := cache.GetResource(localNodeID, typeurl.Secret, "secret")
		_, policyExists := cache.GetResource(localNodeID, typeurl.NetworkPolicy, "policy")
		require.False(t, secretExists)
		require.True(t, policyExists,
			"an SDS NACK must not revert the NetworkPolicy from the same resource update")

		require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:          &envoy_config_core_v3.Node{Id: localNodeID},
			TypeUrl:       NetworkPolicyTypeURL,
			ResponseNonce: policyNonce,
			ErrorDetail:   &status.Status{Message: "rejected policy"},
		}))
		_, policyExists = cache.GetResource(localNodeID, typeurl.NetworkPolicy, "policy")
		require.False(t, policyExists,
			"the SDS rollback must not suppress a later NPDS rollback from the same snapshot")
	})
}

func TestNewADSServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		metrics:              nil,
	}

	server := newADSServer(logger, nil, nil, config, nil, nil)

	require.NotNil(t, server)
	require.NotNil(t, server.logger)
	require.NotNil(t, &server.cache)
	assert.NotEmpty(t, server.socketPath)
	assert.NotEmpty(t, server.accessLogPath)
}

func TestAddListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	wg := completion.NewWaitGroup(ctx)

	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		if err != nil {
			t.Logf("callback received error: %v", err)
		}
	})

	require.NoError(t, err)

	listeners := cachedListeners(cache, localNodeID)
	require.Len(t, listeners, 1)

	actualListener := listeners["test-listener"]
	require.NotNil(t, actualListener)

	// Build the expected listener via the same production code path.
	expectedListener := server.getListenerConf("test-listener", policy.ParserTypeHTTP, 8080, false, false)

	assert.Equal(t, expectedListener.Name, actualListener.Name)
	assert.True(t, proto.Equal(expectedListener.Address, actualListener.Address))
	for i, addr := range expectedListener.AdditionalAddresses {
		assert.True(t, proto.Equal(addr, actualListener.AdditionalAddresses[i]))
	}
	assert.Len(t, actualListener.ListenerFilters, 2, "expected tls_inspector + cilium.bpf_metadata listener filters")
	assert.Equal(t, "envoy.filters.listener.tls_inspector", actualListener.ListenerFilters[0].Name)
	assert.Equal(t, "cilium.bpf_metadata", actualListener.ListenerFilters[1].Name)
	assert.Len(t, actualListener.FilterChains, 2, "expected plain + TLS HTTP filter chains")
	assert.True(t, proto.Equal(expectedListener.FilterChains[0], actualListener.FilterChains[0]))
	assert.True(t, proto.Equal(expectedListener.FilterChains[1], actualListener.FilterChains[1]))
}

func TestAddListenerCompletesCallbackOnACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)

	var calls atomic.Int32
	callbackErr := make(chan error, 1)
	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		calls.Add(1)
		callbackErr <- err
	})
	require.NoError(t, err)
	require.Equal(t, int32(0), calls.Load())

	watchResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	version := snapshot.GetVersion(ListenerTypeURL)
	require.NotEmpty(t, version)

	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(watchResponse.GetContext(), 1, watchResponse.GetRequest(), resp)
	require.Equal(t, int32(0), calls.Load())

	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
	}))
	require.NoError(t, wg.Wait())
	require.Equal(t, int32(1), calls.Load())
	require.NoError(t, <-callbackErr)
}

func TestAddListenerDuringRestoreDoesNotWaitForACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, restorerPromise)
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)

	var calls atomic.Int32
	require.NoError(t, server.AddListener(t.Context(), "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {
		require.NoError(t, err)
		calls.Add(1)
	}))

	require.NoError(t, wg.Wait())
	require.Equal(t, int32(1), calls.Load())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestNoOpListenerAlreadyAcceptedDoesNotWaitForUnrelatedListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	ctx := t.Context()
	node := &envoy_config_core_v3.Node{Id: localNodeID}

	listener1 := &envoy_config_listener.Listener{Name: "listener-1"}
	initial := xds.NewResources()
	initial.Listeners[listener1.Name] = listener1
	require.NoError(t, server.UpsertEnvoyResources(ctx, initial, nil))
	firstResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	firstVersion := firstResponse.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(firstResponse.GetContext(), 1, firstResponse.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: firstVersion, Nonce: "nonce-1",
		})
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1,
		&envoy_service_discovery.DiscoveryRequest{
			Node: node, TypeUrl: ListenerTypeURL, VersionInfo: firstVersion, ResponseNonce: "nonce-1",
		}))

	listener2 := &envoy_config_listener.Listener{Name: "listener-2"}
	second := xds.NewResources()
	second.Listeners[listener2.Name] = listener2
	require.NoError(t, server.UpsertEnvoyResources(ctx, second, nil))
	secondResponse := createADSWatchResponse(t, cache, ListenerTypeURL, firstVersion)
	secondVersion := secondResponse.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(secondResponse.GetContext(), 1, secondResponse.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: secondVersion, Nonce: "nonce-2",
		})

	var callbackCalls atomic.Int32
	noop := xds.NewResources()
	noop.Listeners[listener1.Name] = listener1
	noop.PortAllocationCallbacks[listener1.Name] = func(context.Context) error {
		callbackCalls.Add(1)
		return nil
	}
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	require.NoError(t, server.UpsertEnvoyResources(ctx, noop, wg))
	require.NoError(t, wg.Wait())
	require.Equal(t, int32(1), callbackCalls.Load())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())

	// A no-op update for listener-2 itself must still attach to the response
	// which is currently awaiting its ACK.
	var listener2CallbackCalls atomic.Int32
	listener2NoOp := xds.NewResources()
	listener2NoOp.Listeners[listener2.Name] = listener2
	listener2NoOp.PortAllocationCallbacks[listener2.Name] = func(context.Context) error {
		listener2CallbackCalls.Add(1)
		return nil
	}
	listener2WG := completion.NewWaitGroup(ctx)
	t.Cleanup(listener2WG.Cancel)
	require.NoError(t, server.UpsertEnvoyResources(ctx, listener2NoOp, listener2WG))
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Equal(t, int32(0), listener2CallbackCalls.Load())

	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1,
		&envoy_service_discovery.DiscoveryRequest{
			Node: node, TypeUrl: ListenerTypeURL, VersionInfo: secondVersion, ResponseNonce: "nonce-2",
		}))
	require.NoError(t, listener2WG.Wait())
	require.Equal(t, int32(1), listener2CallbackCalls.Load())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesNoOpListenerWaitsForCurrentACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)

	resources := xds.NewResources()
	resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), resources, nil))
	response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	version := response.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: version, Nonce: "nonce-1",
		})

	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	require.NoError(t, server.UpdateEnvoyResources(ctx, resources, resources, wg))
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())

	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1,
		&envoy_service_discovery.DiscoveryRequest{
			Node: &envoy_config_core_v3.Node{Id: localNodeID}, TypeUrl: ListenerTypeURL,
			VersionInfo: version, ResponseNonce: "nonce-1",
		}))
	require.NoError(t, wg.Wait())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestAddListenerWithoutWaitGroupCallsCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	var calls atomic.Int32
	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil, func(err error) {
		calls.Add(1)
		require.NoError(t, err)
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
}

func TestAddAdminListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Should not panic and should handle port 0 gracefully
	server.AddAdminListener(ctx, 0, wg)

	// Test with valid port
	server.AddAdminListener(ctx, 9000, wg)

	listeners := cachedListeners(cache, localNodeID)
	actualListener := listeners["envoy-admin-listener"]

	// Build the expected listener via the same production code path.
	expectedListener := server.getAdminListenerConfig(9000)

	require.NotNil(t, actualListener)
	require.Len(t, listeners, 1)
	assert.Equal(t, expectedListener.Name, actualListener.Name)
	assert.True(t, proto.Equal(expectedListener.Address, actualListener.Address))
	for i, addr := range expectedListener.AdditionalAddresses {
		assert.True(t, proto.Equal(addr, actualListener.AdditionalAddresses[i]))
	}
	assert.Len(t, actualListener.FilterChains, 1)
	assert.Len(t, actualListener.FilterChains[0].Filters, 1, "Expected http cpnnection manager filter")
	assert.Equal(t, "envoy.filters.network.http_connection_manager", actualListener.FilterChains[0].Filters[0].Name)
}

func TestAddMetricsListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	// Should not panic and should handle port 0 gracefully
	server.AddMetricsListener(ctx, 0, wg)

	// Test with valid port
	server.AddMetricsListener(ctx, 9001, wg)

	listeners := cachedListeners(cache, localNodeID)
	actualListener := listeners["envoy-prometheus-metrics-listener"]

	// Build the expected listener via the same production code path.
	expectedListener := server.getMetricsListenerConfig(9001)

	require.NotNil(t, actualListener)
	require.Len(t, listeners, 1)
	assert.Equal(t, expectedListener.Name, actualListener.Name)
	assert.True(t, proto.Equal(expectedListener.Address, actualListener.Address))
	for i, addr := range expectedListener.AdditionalAddresses {
		assert.True(t, proto.Equal(addr, actualListener.AdditionalAddresses[i]))
	}
	assert.Len(t, actualListener.FilterChains, 1)
}

func TestRemoveListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()
	wg := completion.NewWaitGroup(ctx)

	err := server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, wg, func(err error) {})
	require.NoError(t, err)

	listeners := cachedListeners(cache, localNodeID)
	require.Len(t, listeners, 1)
	require.NotNil(t, listeners["test-listener"])
	require.Equal(t, int64(1), server.npdsListenerCount.Load())

	server.RemoveListener(ctx, "test-listener", wg)

	removedListeners := cachedListeners(cache, localNodeID)
	require.Empty(t, removedListeners)
	// Removal must not mutate a previously observed copy-on-write view.
	require.NotNil(t, listeners["test-listener"])
	require.NotContains(t, server.listenerCount, "test-listener")
	require.Zero(t, server.npdsListenerCount.Load())
}

func TestRemoveListenerReferenceCount(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	ctx := t.Context()
	require.NoError(t, server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil, nil))
	require.NoError(t, server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil, nil))

	server.RemoveListener(ctx, "test-listener", nil)
	require.Equal(t, uint(1), server.listenerCount["test-listener"])
	require.NotNil(t, cachedListener(t, cache, localNodeID, "test-listener"))
	require.Equal(t, int64(1), server.npdsListenerCount.Load())

	server.RemoveListener(ctx, "test-listener", nil)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")
	require.NotContains(t, server.listenerCount, "test-listener")
	require.Zero(t, server.npdsListenerCount.Load())
}

func TestRemoveListenerNACKRestoresResponseState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	ctx := t.Context()
	node := &envoy_config_core_v3.Node{Id: localNodeID}

	require.NoError(t, server.AddListener(ctx, "test-listener", policy.ParserTypeHTTP, 8080, false, false, nil, nil))
	baselineResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	baselineVersion := baselineResponse.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(
		baselineResponse.GetContext(), 1, baselineResponse.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: baselineVersion, Nonce: "nonce-1",
		})
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1,
		&envoy_service_discovery.DiscoveryRequest{
			Node: node, TypeUrl: ListenerTypeURL, VersionInfo: baselineVersion, ResponseNonce: "nonce-1",
		}))

	// RemoveListener does not expose caller rollback. Its cache transaction is
	// finalized immediately, but the response owns an independent rollback
	// until Envoy ACKs or NACKs it.
	server.RemoveListener(ctx, "test-listener", nil)
	requireNoCachedResource(t, cache, localNodeID, ListenerTypeURL, "test-listener")

	removalResponse := createADSWatchResponse(t, cache, ListenerTypeURL, baselineVersion)
	removedVersion := removalResponse.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(
		removalResponse.GetContext(), 1, removalResponse.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: removedVersion, Nonce: "nonce-2",
		})
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1,
		&envoy_service_discovery.DiscoveryRequest{
			Node: node, TypeUrl: ListenerTypeURL, VersionInfo: baselineVersion, ResponseNonce: "nonce-2",
			ErrorDetail: &status.Status{Message: "rejected listener removal"},
		}))

	require.NotNil(t, cachedListener(t, cache, localNodeID, "test-listener"))
	require.NotContains(t, server.listenerCount, "test-listener",
		"response rollback must not recreate a desired listener reference")
}

// TestUpsertEnvoyResources verifies that Envoy resources can be upserted
func TestUpsertEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	listeners := cachedListeners(cache, localNodeID)
	require.Len(t, listeners, 1)
	require.NotNil(t, listeners["listener1"])
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "endpoint1")
	policies := cachedNetworkPolicies(cache, localNodeID)
	require.Len(t, policies, 1)
	require.NotNil(t, policies["40"])
}

func TestUpdateEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}

	cache := xdsnew.NewCache(logger, true)

	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	oldResources := DEFAULT_RESOURCES

	// In the resource new version, second route was added and all secrets got cleared.
	newResources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener1": {
				Name: "listener1",
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 8080,
							},
						},
					},
				},
				FilterChains: []*envoy_config_listener.FilterChain{{
					Filters: []*envoy_config_listener.Filter{
						{
							Name: "envoy.http_connection_manager",
							ConfigType: &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
									StatPrefix: "http_proxy",
									RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
										Rds: &envoy_config_http.Rds{
											RouteConfigName: "routeConfig1",
										},
									},
								}),
							},
						},
						{
							Name: "envoy.http_connection_manager",
							ConfigType: &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: ToAny(&envoy_config_http.HttpConnectionManager{
									StatPrefix: "http_proxy",
									RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
										Rds: &envoy_config_http.Rds{
											RouteConfigName: "routeConfig2",
										},
									},
								}),
							},
						},
					},
				}},
			},
		},
		Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster1": {
				Name:           "cluster1",
				LoadAssignment: &DEFAULT_CLA,
				ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
					Type: *envoy_config_cluster.Cluster_EDS.Enum(),
				},
			},
		},
		Secrets: map[string]*envoy_config_tls.Secret{},
		Routes: map[string]*envoy_config_route.RouteConfiguration{
			"routeConfig1": {
				Name: "routeConfig1",
			},
			"routeConfig2": {
				Name: "routeConfig2",
			},
		},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{
			"endpoint1": &DEFAULT_CLA,
		},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{
			"40": {
				EndpointId: 40,
			},
		},
	}

	err := server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	assert.NoError(t, err)
	listeners := cachedListeners(cache, localNodeID)
	require.Len(t, listeners, 1)
	require.NotNil(t, listeners["listener1"])
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig2")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "endpoint1")
	policies := cachedNetworkPolicies(cache, localNodeID)
	require.Len(t, policies, 1)
	require.NotNil(t, policies["40"])
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
	tests := []struct {
		name   string
		mode   config.XDSMode
		strict bool
	}{
		{name: "ads", mode: config.EnvoyXDSModeADS},
		{name: "strict ads", mode: config.EnvoyXDSModeStrictADS, strict: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			serverConfig := xdsServerConfig{
				envoySocketDir:       t.TempDir(),
				policyRestoreTimeout: 30 * time.Second,
				envoyXDSMode:         tt.mode,
			}
			cache := xdsnew.NewCache(logger, tt.strict)
			server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

			oldResources := adsTestResources(adsTestListener(80, 8443))
			require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))

			newResources := adsTestResources(adsTestListener(80, 8444))
			var callbackCount atomic.Uint64
			newResources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
				callbackCount.Add(1)
				return nil
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
			}()

			require.Eventually(t, func() bool {
				listeners := cachedListeners(cache, localNodeID)
				return len(listeners) == 0 &&
					cache.GetCompletionCallbacks().PendingCompletionCount() == 1
			}, time.Second, 10*time.Millisecond)
			require.Equal(t, uint64(0), callbackCount.Load())
			deleteVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

			require.Eventually(t, func() bool {
				listener := cachedListeners(cache, localNodeID)["listener1"]
				return listener != nil && listenerAddressesEqual(listener, newResources.Listeners["listener1"]) &&
					cache.GetCompletionCallbacks().PendingCompletionCount() == 1
			}, time.Second, 10*time.Millisecond)
			require.Equal(t, uint64(0), callbackCount.Load())
			replaceVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)
			require.NotEqual(t, deleteVersion, replaceVersion)

			require.NoError(t, <-result)
			require.Equal(t, uint64(0), callbackCount.Load())
			require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
		})
	}
}

func TestUpdateEnvoyResourcesDuringRestoreDoesNotStageListenerDeletion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, false)
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, restorerPromise)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(81, 8444))
	var callbackCount atomic.Uint64
	newResources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)

	require.NoError(t, server.UpdateEnvoyResources(t.Context(), oldResources, newResources, wg))
	require.NoError(t, wg.Wait())
	require.Same(t, newResources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1"))
	require.Equal(t, uint64(1), callbackCount.Load())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesAddressChangeSupersedesOlderRollback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := &revertCapturingADSCache{Cache: xdsnew.NewCache(logger, false)}
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	initial := adsTestResources(adsTestListener(80, 8442))
	require.NoError(t, server.UpsertEnvoyResources(ctx, initial, nil))
	cache.revertFuncs = nil

	tracked := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(ctx, tracked, nil))
	require.Len(t, cache.revertFuncs, 1)
	staleRevert := cache.revertFuncs[0]

	desired := adsTestResources(adsTestListener(80, 8444))
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, tracked, desired, nil)
	}()

	require.Eventually(t, func() bool {
		return len(cachedListeners(cache, localNodeID)) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.Eventually(t, func() bool {
		return cachedListeners(cache, localNodeID)["listener1"] == desired.Listeners["listener1"] &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	ackADSResourceVersion(t, cache, 1, ListenerTypeURL)
	require.NoError(t, <-result)

	_, reverted := staleRevert(revertCurrentGeneration)
	require.False(t, reverted)
	require.Same(t, desired.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1"))
}

func TestUpdateEnvoyResourcesRestoresListenerWhenDeletionIsRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(ctx, oldResources, nil))
	acceptedVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)
	newResources := adsTestResources(adsTestListener(80, 8444))

	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	}()

	require.Eventually(t, func() bool {
		return len(cachedListeners(cache, localNodeID)) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)

	response := createADSWatchResponse(t, cache, ListenerTypeURL, acceptedVersion)
	rejectedVersion := response.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(
		response.GetContext(), 1, response.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl:     ListenerTypeURL,
			VersionInfo: rejectedVersion,
		})
	nackResult := make(chan error, 1)
	go func() {
		nackResult <- cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
			Node:        &envoy_config_core_v3.Node{Id: localNodeID},
			TypeUrl:     ListenerTypeURL,
			VersionInfo: acceptedVersion,
			ErrorDetail: &status.Status{Message: "rejected listener deletion"},
		})
	}()
	select {
	case err := <-nackResult:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("listener deletion NACK deadlocked with the ADS transaction")
	}

	select {
	case err := <-result:
		require.ErrorContains(t, err, "rejected listener deletion")
	case <-time.After(time.Second):
		t.Fatal("listener address transaction did not finish after deletion NACK")
	}
	require.Same(t, oldResources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1"))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRestoresListenerWhenDeletionTimesOut(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	listener := cachedListener(t, cache, localNodeID, "listener1")
	require.True(t, listenerAddressesEqual(listener, oldResources.Listeners["listener1"]))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRestoresListenerWhenReplacementIsCanceled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	}()

	require.Eventually(t, func() bool {
		return len(cachedListeners(cache, localNodeID)) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.Eventually(t, func() bool {
		return cachedListeners(cache, localNodeID)["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	cancel()

	require.ErrorIs(t, <-result, context.Canceled)
	require.Same(t, oldResources.Listeners["listener1"], cachedListener(t, cache, localNodeID, "listener1"))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRestoresListenerWhenReplacementIsRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	}()

	require.Eventually(t, func() bool {
		listeners := cachedListeners(cache, localNodeID)
		return len(listeners) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	deleteVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.Eventually(t, func() bool {
		return cachedListeners(cache, localNodeID)["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, deleteVersion, "rejected listener")
	require.ErrorContains(t, <-result, "rejected listener")

	listener := cachedListener(t, cache, localNodeID, "listener1")
	require.True(t, listenerAddressesEqual(listener, oldResources.Listeners["listener1"]))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesRetriesReplacementBindFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverConfig := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeADS,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, serverConfig, nil, nil)

	oldResources := adsTestResources(adsTestListener(80, 8443))
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), oldResources, nil))
	newResources := adsTestResources(adsTestListener(80, 8444))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- server.UpdateEnvoyResources(ctx, oldResources, newResources, nil)
	}()

	require.Eventually(t, func() bool {
		listeners := cachedListeners(cache, localNodeID)
		return len(listeners) == 0 &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	deleteVersion := ackADSResourceVersion(t, cache, 1, ListenerTypeURL)

	require.Eventually(t, func() bool {
		return cachedListeners(cache, localNodeID)["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	nackADSResourceVersion(t, cache, 1, ListenerTypeURL, deleteVersion, "cannot bind: Address already in use")

	// The rejected desired version is first replaced with the accepted deletion
	// version, then published again after the retry delay.
	require.Eventually(t, func() bool {
		return len(cachedListeners(cache, localNodeID)) == 0
	}, time.Second, 10*time.Millisecond)
	retryRequest := &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ListenerTypeURL,
		VersionInfo: deleteVersion,
	}
	retryResponses := make(chan xds_cache.Response, 1)
	cancelRetryWatch, err := cache.CreateWatch(
		retryRequest, envoy_stream.NewSotwSubscription(nil, false), retryResponses)
	require.NoError(t, err)
	t.Cleanup(cancelRetryWatch)

	require.Eventually(t, func() bool {
		return cachedListeners(cache, localNodeID)["listener1"] != nil &&
			cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	var retryResponse xds_cache.Response
	select {
	case retryResponse = <-retryResponses:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for retried listener response")
	}
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	retryVersion := snapshot.GetVersion(ListenerTypeURL)
	cache.GetCompletionCallbacks().OnStreamResponse(
		retryResponse.GetContext(), 1, retryResponse.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl:     ListenerTypeURL,
			VersionInfo: retryVersion,
		})
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ListenerTypeURL,
		VersionInfo: retryVersion,
	}))

	require.NoError(t, <-result)
	listener := cachedListener(t, cache, localNodeID, "listener1")
	require.True(t, listenerAddressesEqual(listener, newResources.Listeners["listener1"]))
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesWithoutExplicitCallbackDoesNotWaitForCDSOrRDS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	oldResources := xds.NewResources()
	oldResources.Listeners["listener1"] = DEFAULT_RESOURCES.Listeners["listener1"]
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), oldResources, nil))
	response := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	version := response.GetResponseVersion()
	cache.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			TypeUrl: ListenerTypeURL, VersionInfo: version, Nonce: "nonce-1",
		})
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1,
		&envoy_service_discovery.DiscoveryRequest{
			Node: &envoy_config_core_v3.Node{Id: localNodeID}, TypeUrl: ListenerTypeURL,
			VersionInfo: version, ResponseNonce: "nonce-1",
		}))

	newResources := xds.NewResources()
	newResources.Listeners["listener1"] = DEFAULT_RESOURCES.Listeners["listener1"]
	newResources.Clusters["cluster1"] = DEFAULT_RESOURCES.Clusters["cluster1"]
	newResources.Routes["routeConfig1"] = DEFAULT_RESOURCES.Routes["routeConfig1"]

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, oldResources, newResources, wg))

	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.NoError(t, wg.Wait())
}

func TestUpdateEnvoyResourcesWaitsForListenerACKWithPortAllocationCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resources := xds.NewResources()
	resources.Listeners["listener1"] = DEFAULT_RESOURCES.Listeners["listener1"]
	var callbackCount atomic.Uint64
	resources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), resources, wg))

	require.Eventually(t, func() bool {
		return cache.GetCompletionCallbacks().PendingCompletionCount() == 1
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(0), callbackCount.Load())

	watchResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	version := snapshot.GetVersion(ListenerTypeURL)
	require.NotEmpty(t, version)

	resp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(watchResponse.GetContext(), 1, watchResponse.GetRequest(), resp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ListenerTypeURL,
		VersionInfo: version,
	}))

	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(1), callbackCount.Load())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesWithPortAllocationWaitsForClusterAndListenerACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, false)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resources := DEFAULT_RESOURCES
	resources.PortAllocationCallbacks = make(map[string]func(context.Context) error)
	var callbackCount atomic.Uint64
	resources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, xds.NewResources(), resources, wg))

	require.Eventually(t, func() bool {
		return cache.GetCompletionCallbacks().PendingCompletionCount() == 2
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(0), callbackCount.Load())

	clusterWatchResponse := createADSWatchResponse(t, cache, ClusterTypeURL, "")
	snapshot, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	listenerVersion := snapshot.GetVersion(ListenerTypeURL)
	clusterVersion := snapshot.GetVersion(ClusterTypeURL)
	require.NotEmpty(t, listenerVersion)
	require.NotEmpty(t, clusterVersion)
	require.NotEmpty(t, snapshot.GetVersion(RouteTypeURL))
	listenerWatchResponse := createADSWatchResponse(t, cache, ListenerTypeURL, "")

	clusterResp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ClusterTypeURL,
		VersionInfo: clusterVersion,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(clusterWatchResponse.GetContext(), 1, clusterWatchResponse.GetRequest(), clusterResp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ClusterTypeURL,
		VersionInfo: clusterVersion,
	}))
	require.Equal(t, uint64(0), callbackCount.Load())
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())

	listenerResp := &envoy_service_discovery.DiscoveryResponse{
		TypeUrl:     ListenerTypeURL,
		VersionInfo: listenerVersion,
	}
	cache.GetCompletionCallbacks().OnStreamResponse(listenerWatchResponse.GetContext(), 1, listenerWatchResponse.GetRequest(), listenerResp)
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl:     ListenerTypeURL,
		VersionInfo: listenerVersion,
	}))

	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(1), callbackCount.Load())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestUpdateEnvoyResourcesWithConfirmedPortAllocationDoesNotWaitForChangedClusters(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	oldResources := DEFAULT_RESOURCES
	require.NoError(t, server.UpsertEnvoyResources(ctx, oldResources, nil))

	newResources := DEFAULT_RESOURCES
	newResources.Routes = maps.Clone(DEFAULT_RESOURCES.Routes)
	newResources.Clusters = maps.Clone(DEFAULT_RESOURCES.Clusters)
	newResources.PortAllocationCallbacks = make(map[string]func(context.Context) error)
	newResources.Routes["routeConfig2"] = &envoy_config_route.RouteConfiguration{Name: "routeConfig2"}
	newResources.Clusters["cluster2"] = &envoy_config_cluster.Cluster{
		Name: "cluster2",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
	}
	var callbackCount atomic.Uint64
	newResources.PortAllocationCallbacks["listener1"] = func(context.Context) error {
		callbackCount.Add(1)
		return nil
	}

	wg := completion.NewWaitGroup(ctx)
	require.NoError(t, server.UpdateEnvoyResources(ctx, oldResources, newResources, wg))

	require.NoError(t, wg.Wait())
	require.Equal(t, uint64(0), callbackCount.Load())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())

	_, routeExists := cache.GetResource(localNodeID, typeurl.Route, "routeConfig2")
	require.True(t, routeExists)
	_, clusterExists := cache.GetResource(localNodeID, typeurl.Cluster, "cluster2")
	require.True(t, clusterExists)
}

func TestUpdateEnvoyResourcesRejectsInconsistentSnapshotInStrictADSMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
		envoyXDSMode:         config.EnvoyXDSModeStrictADS,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)

	resources := xds.NewResources()
	resources.Listeners["listener1"] = proto.Clone(DEFAULT_RESOURCES.Listeners["listener1"]).(*envoy_config_listener.Listener)

	require.NoError(t, server.UpsertEnvoyResources(context.Background(), resources, nil))
	responses := make(chan xds_cache.Response, 1)
	_, err := cache.CreateWatch(&envoy_service_discovery.DiscoveryRequest{
		Node:    &envoy_config_core_v3.Node{Id: localNodeID},
		TypeUrl: ListenerTypeURL,
	}, envoy_stream.NewSotwSubscription(nil, false), responses)
	require.ErrorContains(t, err, "generated ADS snapshot is inconsistent")
}

func TestDeleteEnvoyResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	xdsResources := xds.Resources{
		Listeners:       map[string]*envoy_config_listener.Listener{},
		Clusters:        map[string]*envoy_config_cluster.Cluster{},
		Routes:          map[string]*envoy_config_route.RouteConfiguration{},
		Endpoints:       map[string]*envoy_config_endpoint.ClusterLoadAssignment{},
		Secrets:         map[string]*envoy_config_tls.Secret{},
		NetworkPolicies: map[string]*cilium.NetworkPolicy{},
	}

	// Deleting empty resources should be no-op.
	err := server.DeleteEnvoyResources(ctx, xdsResources, nil)
	assert.NoError(t, err)
	require.Empty(t, cachedListeners(cache, localNodeID))
	require.Empty(t, cachedNetworkPolicies(cache, localNodeID))

	// Add some resources and then delete them.
	err = server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	listeners := cachedListeners(cache, localNodeID)
	require.Len(t, listeners, 1)
	require.NotNil(t, listeners["listener1"])
	requireCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireCachedResource(t, cache, localNodeID, EndpointTypeURL, "endpoint1")
	policies := cachedNetworkPolicies(cache, localNodeID)
	require.Len(t, policies, 1)
	require.NotNil(t, policies["40"])

	err = server.DeleteEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)
	require.Empty(t, cachedListeners(cache, localNodeID))
	requireNoCachedResource(t, cache, localNodeID, ClusterTypeURL, "cluster1")
	requireNoCachedResource(t, cache, localNodeID, SecretTypeURL, "secret1")
	requireNoCachedResource(t, cache, localNodeID, RouteTypeURL, "routeConfig1")
	requireNoCachedResource(t, cache, localNodeID, EndpointTypeURL, "endpoint1")
	require.Empty(t, cachedNetworkPolicies(cache, localNodeID))
}

func TestGetNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, nil, config, nil, nil)
	ctx := context.Background()

	server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)

	// Get all network policies — result is keyed by endpoint IP, not endpoint ID.
	policies, err := server.GetNetworkPolicies(nil)
	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.NotNil(t, policies["10.0.0.1"], "policy should be keyed by endpoint IP")
	assert.Nil(t, policies["40"], "policy should not be keyed by endpoint ID")
	assert.Equal(t, uint64(40), policies["10.0.0.1"].EndpointId)

	// Filter by resource name (endpoint ID string).
	policies, err = server.GetNetworkPolicies([]string{"40"})
	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.NotNil(t, policies["10.0.0.1"], "filtered policy should be keyed by endpoint IP")

	policies, err = server.GetNetworkPolicies([]string{"nonexistent"})
	assert.NoError(t, err)
	assert.NotNil(t, policies)
	assert.Empty(t, policies)
}

func TestUpdateNetworkPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	wg := completion.NewWaitGroup(ctx)

	// Create a mock endpoint updater
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}

	// Create a mock policy
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc, _ := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	// This may return an error if policy is nil or invalid
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, revertFunc)
	}

	policies := cachedNetworkPolicies(cache, localNodeID)
	require.Len(t, policies, 2)
	require.NotNil(t, policies["40"])
	assert.Equal(t, uint64(40), policies["40"].EndpointId)
	require.NotNil(t, policies["1"])
	assert.Equal(t, uint64(1), policies["1"].EndpointId)
}

func TestUpdateNetworkPolicyReusesIdempotentCacheRevert(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := &revertCapturingADSCache{Cache: xdsnew.NewCache(logger, true)}
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := t.Context()

	previousPolicy := &cilium.NetworkPolicy{
		EndpointId:  1,
		EndpointIps: []string{"192.0.2.1"},
	}
	resources := xds.NewResources()
	resources.NetworkPolicies["1"] = previousPolicy
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	cache.revertFuncs = nil

	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	err, revertFunc, _ := server.UpdateNetworkPolicy(ctx, ep, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revertFunc)
	require.Len(t, cache.revertFuncs, 1)
	require.False(t, proto.Equal(previousPolicy, cachedNetworkPolicy(t, cache, localNodeID, "1")))

	// Simulate the cache's NACK path invoking the revert before endpoint
	// regeneration reports failure to its caller.
	generationAfterNACK, reverted := cache.revertFuncs[0](revertCurrentGeneration)
	require.True(t, reverted)
	require.Same(t, previousPolicy, cachedNetworkPolicy(t, cache, localNodeID, "1"))

	require.NoError(t, revertFunc())
	replayedGeneration, replayed := cache.revertFuncs[0](revertCurrentGeneration)
	require.False(t, replayed)
	require.Equal(t, generationAfterNACK, replayedGeneration)
	require.Same(t, previousPolicy, cachedNetworkPolicy(t, cache, localNodeID, "1"))
}

func TestUpdateNetworkPolicyRevertAfterLaterResourceUpdate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := t.Context()

	previousPolicy := &cilium.NetworkPolicy{
		EndpointId:  1,
		EndpointIps: []string{"192.0.2.1"},
	}
	resources := xds.NewResources()
	resources.NetworkPolicies["1"] = previousPolicy
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))

	ep1 := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	err, revertPolicy1, _ := server.UpdateNetworkPolicy(ctx, ep1, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, revertPolicy1)

	// A different endpoint can advance the node generation before broader
	// endpoint regeneration decides to roll the first update back.
	ep2 := &testableEndpointUpdater{id: 2, ipv4: "127.0.0.2"}
	err, _, _ = server.UpdateNetworkPolicy(ctx, ep2, epp, nil)
	require.NoError(t, err)
	_, exists := cache.GetResource(localNodeID, typeurl.NetworkPolicy, "2")
	require.True(t, exists)

	require.NoError(t, revertPolicy1())
	current := cachedNetworkPolicies(cache, localNodeID)
	require.Same(t, previousPolicy, current["1"])
	require.Contains(t, current, "2")
}

func TestUpdateNetworkPolicyRevertPreservesNewerPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := t.Context()

	previousPolicy := &cilium.NetworkPolicy{
		EndpointId:  1,
		EndpointIps: []string{"192.0.2.1"},
	}
	resources := xds.NewResources()
	resources.NetworkPolicies["1"] = previousPolicy
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))

	epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	err, staleRevert, _ := server.UpdateNetworkPolicy(ctx, ep, epp, nil)
	require.NoError(t, err)
	require.NotNil(t, staleRevert)

	newerEP := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.2"}
	err, _, _ = server.UpdateNetworkPolicy(ctx, newerEP, epp, nil)
	require.NoError(t, err)
	newerPolicy := cachedNetworkPolicy(t, cache, localNodeID, "1")
	require.Contains(t, newerPolicy.EndpointIps, "127.0.0.2")

	require.NoError(t, staleRevert())
	require.Same(t, newerPolicy, cachedNetworkPolicy(t, cache, localNodeID, "1"))
}

func TestUpdateNetworkPolicyWithoutNPDSListenersCompletesImmediately(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()
	require.NoError(t, server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil))
	require.False(t, server.hasNPDSListeners())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc, finalizeFunc := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertFunc)
	require.NotNil(t, finalizeFunc)
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 1
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, wg.Wait())
}

func TestUpdateNetworkPolicyDuringRestoreDoesNotWaitForACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), restorerPromise)

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), resources, nil))
	require.True(t, server.hasNPDSListeners())

	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc, finalizeFunc := server.UpdateNetworkPolicy(t.Context(), mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertFunc)
	require.NotNil(t, finalizeFunc)
	finalizeFunc()
	require.NoError(t, wg.Wait())
	require.Zero(t, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

func TestUpdateNetworkPolicyWithNPDSListenerWaitsForACK(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	require.True(t, server.hasNPDSListeners())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc, finalizeFunc := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.NotNil(t, revertFunc)
	require.NotNil(t, finalizeFunc)
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	require.Equal(t, uint64(0), mockEp.proxyPolicyUpdateCount.Load())

	cache.GetCompletionCallbacks().CancelPendingCompletions(typeurl.NetworkPolicy)
	require.Eventually(t, func() bool {
		return mockEp.proxyPolicyUpdateCount.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

func TestUpdateNetworkPolicyCancelsWaitWhenLastNPDSListenerIsRemovedBeforeRegistration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	baseCache := xdsnew.NewCache(logger, true)
	cache := &blockingNetworkPolicyADSCache{
		Cache:          baseCache,
		upsertStarted:  make(chan struct{}),
		continueUpsert: make(chan struct{}),
	}
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	listener := server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	updated, listenerRevert, _, err := baseCache.UpsertListener(ctx, localNodeID, listener.Name, listener, nil, nil)
	require.NoError(t, err)
	require.True(t, updated)
	require.NotNil(t, listenerRevert)
	require.True(t, server.hasNPDSListeners())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	type updateResult struct {
		err          error
		revertFunc   revert.RevertFunc
		finalizeFunc revert.FinalizeFunc
	}
	result := make(chan updateResult, 1)
	go func() {
		err, revertFunc, finalizeFunc := server.UpdateNetworkPolicy(
			ctx,
			&testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"},
			policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot()),
			wg,
		)
		result <- updateResult{err: err, revertFunc: revertFunc, finalizeFunc: finalizeFunc}
	}()

	select {
	case <-cache.upsertStarted:
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for the NetworkPolicy upsert")
	}

	// Model a cache-owned listener rollback after UpdateNetworkPolicy has
	// decided to wait, but before its completion is registered in the cache.
	_, reverted := listenerRevert(0)
	require.True(t, reverted)
	require.False(t, server.hasNPDSListeners())
	require.Zero(t, baseCache.GetCompletionCallbacks().PendingCompletionCount())
	close(cache.continueUpsert)

	var update updateResult
	select {
	case update = <-result:
	case <-time.After(time.Second):
		require.FailNow(t, "timed out waiting for the NetworkPolicy update")
	}
	require.NoError(t, update.err)
	require.NotNil(t, update.revertFunc)
	require.NotNil(t, update.finalizeFunc)
	defer update.finalizeFunc()
	require.Zero(t, baseCache.GetCompletionCallbacks().PendingCompletionCount())
	require.NoError(t, wg.Wait())
}

func TestUpdateNetworkPolicyNoOpWaitsForCurrentACKWithoutPublishing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := &countingADSCache{Cache: xdsnew.NewCache(logger, true)}
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	require.True(t, server.hasNPDSListeners())

	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	firstWG := completion.NewWaitGroup(ctx)
	defer firstWG.Cancel()
	err, _, _ := server.UpdateNetworkPolicy(ctx, ep, epp, firstWG)
	require.NoError(t, err)
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())
	response := createADSWatchResponse(t, cache, NetworkPolicyTypeURL, "")

	// Advance the node-wide generation with an unrelated Listener while the
	// response carrying the policy is still in the delivery handoff.
	intervening := xds.NewResources()
	intervening.Listeners["intervening-listener"] = server.getListenerConf(
		"intervening-listener", policy.ParserTypeHTTP, 12346, false, false)
	require.NoError(t, server.UpsertEnvoyResources(ctx, intervening, nil))

	policyBefore := cachedNetworkPolicy(t, cache, localNodeID, "1")
	snapshotBefore, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	require.Equal(t, response.GetResponseVersion(), snapshotBefore.GetVersion(NetworkPolicyTypeURL))
	cache.reset()

	secondWG := completion.NewWaitGroup(ctx)
	defer secondWG.Cancel()
	err, noOpRevert, finalize := server.UpdateNetworkPolicy(ctx, ep, epp, secondWG)
	require.NoError(t, err)
	require.NotNil(t, noOpRevert)
	require.NotNil(t, finalize)
	require.Zero(t, cache.generated.Load())
	require.Zero(t, cache.published.Load())
	require.Same(t, policyBefore, cachedNetworkPolicy(t, cache, localNodeID, "1"))
	snapshotAfter, err := cache.GetSnapshot(localNodeID)
	require.NoError(t, err)
	require.Same(t, snapshotBefore, snapshotAfter)
	require.Equal(t, 2, cache.GetCompletionCallbacks().PendingCompletionCount())

	version := response.GetResponseVersion()
	node := &envoy_config_core_v3.Node{Id: localNodeID}
	cache.GetCompletionCallbacks().OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&envoy_service_discovery.DiscoveryResponse{
			VersionInfo: version,
			TypeUrl:     NetworkPolicyTypeURL,
		})
	require.NoError(t, cache.GetCompletionCallbacks().OnStreamRequest(1, &envoy_service_discovery.DiscoveryRequest{
		Node:        node,
		TypeUrl:     NetworkPolicyTypeURL,
		VersionInfo: version,
	}))
	require.NoError(t, firstWG.Wait())
	require.NoError(t, secondWG.Wait())
	require.Eventually(t, func() bool {
		return ep.proxyPolicyUpdateCount.Load() == 2
	}, time.Second, 10*time.Millisecond)

	require.NoError(t, noOpRevert())
	require.Zero(t, cache.generated.Load())
	require.Zero(t, cache.published.Load())
	require.Same(t, policyBefore, cachedNetworkPolicy(t, cache, localNodeID, "1"))
}

func TestUpdateNetworkPolicyPreservesUnchangedResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()

	resources := xds.NewResources()
	resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
	resources.NetworkPolicies["1"] = &cilium.NetworkPolicy{
		EndpointId:  1,
		EndpointIps: []string{"192.0.2.1"},
	}
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	oldPolicy, exists := cache.GetResource(localNodeID, typeurl.NetworkPolicy, "1")
	require.True(t, exists)
	oldListener, exists := cache.GetResource(localNodeID, typeurl.Listener, "listener")
	require.True(t, exists)

	ep := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	epp := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	err, _, _ := server.UpdateNetworkPolicy(ctx, ep, epp, nil)
	require.NoError(t, err)

	newPolicy, exists := cache.GetResource(localNodeID, typeurl.NetworkPolicy, "1")
	require.True(t, exists)
	newListener, exists := cache.GetResource(localNodeID, typeurl.Listener, "listener")
	require.True(t, exists)
	require.False(t, proto.Equal(oldPolicy, newPolicy))
	require.Same(t, oldListener, newListener)
}

func TestNPDSListenerStateFromBulkResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()

	resources := xds.NewResources()
	resources.Listeners["npds-listener"] = server.getListenerConf("npds-listener", policy.ParserTypeHTTP, 12345, false, false)
	require.NoError(t, server.UpsertEnvoyResources(ctx, resources, nil))
	require.True(t, server.hasNPDSListeners())

	wg := completion.NewWaitGroup(ctx)
	defer wg.Cancel()
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())
	err, _, _ := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	require.NoError(t, err)
	require.Equal(t, 1, cache.GetCompletionCallbacks().PendingCompletionCount())

	require.NoError(t, server.DeleteEnvoyResources(ctx, resources, nil))
	require.False(t, server.hasNPDSListeners())
	require.Equal(t, 0, cache.GetCompletionCallbacks().PendingCompletionCount())
}

func TestNPDSListenerCountFromBulkResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), xdsServerConfig{}, certificatemanager.NewMockSecretManagerInline(), nil)

	resources := xds.NewResources()
	resources.Listeners["npds-listener-1"] = server.getListenerConf("npds-listener-1", policy.ParserTypeHTTP, 12345, false, false)
	resources.Listeners["npds-listener-2"] = server.getListenerConf("npds-listener-2", policy.ParserTypeHTTP, 12346, false, false)
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), resources, nil))
	require.Equal(t, int64(2), server.npdsListenerCount.Load())

	first := xds.NewResources()
	first.Listeners["npds-listener-1"] = resources.Listeners["npds-listener-1"]
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), first, nil))
	require.Equal(t, int64(1), server.npdsListenerCount.Load())
	require.True(t, server.hasNPDSListeners())

	second := xds.NewResources()
	second.Listeners["npds-listener-2"] = resources.Listeners["npds-listener-2"]
	replacement := xds.NewResources()
	replacement.Listeners["npds-listener-3"] = server.getListenerConf("npds-listener-3", policy.ParserTypeHTTP, 12347, false, false)
	require.NoError(t, server.UpdateEnvoyResources(t.Context(), second, replacement, nil))
	require.Equal(t, int64(1), server.npdsListenerCount.Load(), "one transaction must apply one aggregate delta")
	require.True(t, server.hasNPDSListeners())

	require.NoError(t, server.DeleteEnvoyResources(t.Context(), replacement, nil))
	require.Zero(t, server.npdsListenerCount.Load())
	require.False(t, server.hasNPDSListeners())
}

func TestRemoveNetworkPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, nil, nil)

	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	policies := cachedNetworkPolicies(cache, localNodeID)
	require.Len(t, policies, 1)

	// Create a mock endpoint info source
	mockEp := &mockEndpointInfoSource{}

	// Should not panic
	server.RemoveNetworkPolicy(ctx, mockEp)

	policies = cachedNetworkPolicies(cache, localNodeID)
	require.Empty(t, policies)
}

// TestRemoveAllNetworkPolicies verifies that all network policies can be removed
func TestRemoveAllNetworkPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 30 * time.Second,
	}
	cache := xdsnew.NewCache(logger, true)
	server := newADSServerWithCache(cache, logger, nil, GetLocalEndpointStoreForTest(), config, certificatemanager.NewMockSecretManagerInline(), nil)
	ctx := context.Background()
	err := server.UpsertEnvoyResources(ctx, DEFAULT_RESOURCES, nil)
	assert.NoError(t, err)

	wg := completion.NewWaitGroup(ctx)

	// Create a mock endpoint updater
	mockEp := &testableEndpointUpdater{id: 1, ipv4: "127.0.0.1"}

	// Create a mock policy
	mockPolicy := policy.NewEndpointPolicyForTest(types.MockSelectorSnapshot())

	err, revertFunc, _ := server.UpdateNetworkPolicy(ctx, mockEp, mockPolicy, wg)
	// This may return an error if policy is nil or invalid
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, revertFunc)
	}

	policies := cachedNetworkPolicies(cache, localNodeID)
	require.Len(t, policies, 2)
	require.NotNil(t, policies["40"])
	require.NotNil(t, policies["1"])

	server.RemoveAllNetworkPolicies()
	policies = cachedNetworkPolicies(cache, localNodeID)
	require.Empty(t, policies)
}

// Mock types for testing

type mockEndpointInfoSource struct{}

func (m *mockEndpointInfoSource) GetID() uint64 {
	return 40
}

func (m *mockEndpointInfoSource) GetIPv4Address() string {
	return "127.0.0.1"
}

func (m *mockEndpointInfoSource) GetIPv6Address() string {
	return ""
}

func (m *mockEndpointInfoSource) GetPolicyNames() []string {
	return []string{"40"}
}

func (m *mockEndpointInfoSource) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 {
	return 0
}

// testableEndpointUpdater is a configurable mock implementing endpoint.EndpointUpdater.
type testableEndpointUpdater struct {
	id                     uint64
	ipv4                   string
	ipv6                   string
	proxyPolicyRevision    atomic.Uint64
	proxyPolicyUpdateCount atomic.Uint64
}

func (m *testableEndpointUpdater) GetID() uint64          { return m.id }
func (m *testableEndpointUpdater) GetIPv4Address() string { return m.ipv4 }
func (m *testableEndpointUpdater) GetIPv6Address() string { return m.ipv6 }
func (m *testableEndpointUpdater) GetPolicyNames() []string {
	var res []string
	if m.ipv4 != "" {
		res = append(res, m.ipv4)
	}
	if m.ipv6 != "" {
		res = append(res, m.ipv6)
	}
	return res
}
func (m *testableEndpointUpdater) GetIngressNamedPort(string, u8proto.U8proto) uint16 { return 0 }
func (m *testableEndpointUpdater) OnProxyPolicyUpdate(revision uint64) {
	m.proxyPolicyRevision.Store(revision)
	m.proxyPolicyUpdateCount.Add(1)
}
func (m *testableEndpointUpdater) UpdateProxyStatistics(string, string, uint16, uint16, bool, bool, accesslog.FlowVerdict) {
}
func (m *testableEndpointUpdater) GetListenerProxyPort(string) uint16 { return 0 }

// mockRestorer implements endpointstate.Restorer for testing.
type mockRestorer struct {
	waitErr error
}

func (m *mockRestorer) WaitForEndpointRestore(ctx context.Context) error {
	return m.waitErr
}

func (m *mockRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return m.waitErr
}

func (m *mockRestorer) WaitForInitialPolicy(ctx context.Context) error {
	return m.waitErr
}

func TestStartAdsGRPCServerWithRestorerSuccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Resolve the promise with a restorer that succeeds.
	resolver.Resolve(&mockRestorer{waitErr: nil})

	// Wait briefly for the server to start serving.
	time.Sleep(200 * time.Millisecond)

	// Server should be running; stop it and verify no error.
	require.NotNil(t, server.stopFunc, "stopFunc should be set after gRPC server is created")
	server.stopFunc()

	err := <-errCh
	assert.NoError(t, err)
}

func TestStartAdsGRPCServerWithRestorerDeadlineExceeded(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Resolve with a restorer that returns DeadlineExceeded.
	resolver.Resolve(&mockRestorer{waitErr: context.DeadlineExceeded})

	// Server should still start serving despite the deadline exceeded.
	time.Sleep(200 * time.Millisecond)

	require.NotNil(t, server.stopFunc, "stopFunc should be set even after deadline exceeded")
	server.stopFunc()

	err := <-errCh
	assert.NoError(t, err)
}

func TestStartAdsGRPCServerWithRestorerCanceled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Resolve with a restorer that returns context.Canceled.
	resolver.Resolve(&mockRestorer{waitErr: context.Canceled})

	err := <-errCh
	assert.ErrorIs(t, err, context.Canceled)
}

func TestStartAdsGRPCServerWithNilRestorerPromise(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	server := newADSServer(logger, nil, nil, config, nil, nil)

	ctx := t.Context()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// With nil restorerPromise, server should start immediately.
	time.Sleep(200 * time.Millisecond)

	require.NotNil(t, server.stopFunc, "stopFunc should be set when restorerPromise is nil")
	server.stopFunc()

	err := <-errCh
	assert.NoError(t, err)
}

func TestStartAdsGRPCServerContextCanceledBeforeResolve(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		policyRestoreTimeout: 5 * time.Second,
	}

	_, restorerPromise := promise.New[endpointstate.Restorer]()
	server := newADSServer(logger, nil, nil, config, nil, restorerPromise)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.startAdsGRPCServer(ctx)
	}()

	// Cancel context before resolving the promise — simulates shutdown during startup.
	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-errCh
	assert.ErrorIs(t, err, context.Canceled)
}
