// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/time"
)

func newTestADSClient(t *testing.T, server *adsServer) discovery.AggregatedDiscoveryServiceClient {
	t.Helper()
	transport := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { require.NoError(t, transport.Close()) })
	grpcServer := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, envoy_server.NewServer(t.Context(), server.cache.GetSnapshotCache(), server.newCallbacks(),
		sotw.WithOrderedADS(),
		sotw.DeactivateLegacyWildcardForTypes([]string{EndpointTypeURL, RouteTypeURL, SecretTypeURL}),
	))
	go func() { _ = grpcServer.Serve(transport) }()
	t.Cleanup(grpcServer.Stop)
	conn, err := grpc.NewClient("passthrough:///ads-test", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return transport.DialContext(ctx) }))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return discovery.NewAggregatedDiscoveryServiceClient(conn)
}

func TestADSEmptyNamedSubscriptionStillProcessesACK(t *testing.T) {
	for _, test := range []struct {
		typeURL typeurl.Index
		initial proto.Message
		updated proto.Message
	}{
		{
			typeURL: typeurl.Endpoint,
			initial: &endpoint.ClusterLoadAssignment{ClusterName: "resource"},
			updated: &endpoint.ClusterLoadAssignment{ClusterName: "resource", Endpoints: []*endpoint.LocalityLbEndpoints{{Priority: 1}}},
		},
		{
			typeURL: typeurl.Route,
			initial: &route.RouteConfiguration{Name: "resource"},
			updated: &route.RouteConfiguration{Name: "resource", IgnorePortInHostMatching: true},
		},
		{
			typeURL: typeurl.Secret,
			initial: &tls.Secret{Name: "resource"},
			updated: &tls.Secret{Name: "resource", Type: &tls.Secret_GenericSecret{GenericSecret: &tls.GenericSecret{}}},
		},
	} {
		t.Run(test.typeURL.URL(), func(t *testing.T) {
			server := newTestADSServer(t, hivetest.Logger(t), nil, nil, xdsServerConfig{}, nil, nil)
			client := newTestADSClient(t, server)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			// The bulk server API does not wait for EDS/RDS/SDS. Use the
			// production cache API to observe ACK handling through real gRPC.
			completed := make(chan error, 1)
			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, "resource", test.initial, wg, func(err error) { completed <- err }))
			stream, err := client.StreamAggregatedResources(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
				Node: &core.Node{Id: localNodeID}, TypeUrl: test.typeURL.URL(),
			}))
			// A response to the following LDS request proves the preceding empty
			// subscription was processed without responding. Requests on this ADS
			// stream are handled in order, so no sleeps or receive timeouts are needed.
			require.NoError(t, stream.Send(&discovery.DiscoveryRequest{TypeUrl: ListenerTypeURL}))
			marker, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, ListenerTypeURL, marker.GetTypeUrl())
			select {
			case err := <-completed:
				t.Fatalf("an empty subscription unexpectedly completed the update: %v", err)
			default:
			}

			require.NoError(t, stream.Send(&discovery.DiscoveryRequest{TypeUrl: test.typeURL.URL(), ResourceNames: []string{"resource"}}))
			response, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, test.typeURL.URL(), response.GetTypeUrl())
			require.Len(t, response.GetResources(), 1)
			require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
				TypeUrl: test.typeURL.URL(), VersionInfo: response.GetVersionInfo(), ResponseNonce: response.GetNonce(),
			}))
			// This request ACKs the response and unsubscribes at the same time.
			// CDS provides another ordered marker, proving that ACK processing
			// occurred even though no new watch or full-state response was created.
			require.NoError(t, stream.Send(&discovery.DiscoveryRequest{TypeUrl: ClusterTypeURL}))
			marker, err = stream.Recv()
			require.NoError(t, err)
			require.Equal(t, ClusterTypeURL, marker.GetTypeUrl())
			require.NoError(t, wg.Wait())
			require.NoError(t, <-completed)
			require.Empty(t, completed, "the ACK callback must run exactly once")

			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, "resource", test.updated, nil, nil))
			require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
				TypeUrl: test.typeURL.URL(), ResourceNames: []string{"resource"}, VersionInfo: response.GetVersionInfo(),
			}))
			response, err = stream.Recv()
			require.NoError(t, err)
			require.Equal(t, test.typeURL.URL(), response.GetTypeUrl())
			require.Len(t, response.GetResources(), 1)
			resource, err := response.GetResources()[0].UnmarshalNew()
			require.NoError(t, err)
			require.True(t, proto.Equal(test.updated, resource), "resubscribing must return the latest resource")
		})
	}
}

func TestADSRejectsUnknownNodes(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		mode := config.EnvoyXDSModeADS
		if strictADS {
			mode = config.EnvoyXDSModeStrictADS
		}
		t.Run(string(mode), func(t *testing.T) {
			ipCache := &mockIPCacheEventSource{}
			server := newTestADSServer(t, hivetest.Logger(t), ipCache, nil, xdsServerConfig{envoyXDSMode: mode}, nil, nil)
			client := newTestADSClient(t, server)
			for _, test := range []struct {
				name string
				node *core.Node
				code codes.Code
			}{
				{"unknown", &core.Node{Id: "unknown-node"}, codes.NotFound},
				{"empty", &core.Node{}, codes.InvalidArgument},
				{"missing", nil, codes.InvalidArgument},
			} {
				t.Run(test.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					stream, err := client.StreamAggregatedResources(ctx)
					require.NoError(t, err)
					require.NoError(t, stream.Send(&discovery.DiscoveryRequest{Node: test.node, TypeUrl: NetworkPolicyHostsTypeURL}))
					_, err = stream.Recv()
					require.Equal(t, test.code, status.Code(err))
				})
			}
			require.Zero(t, ipCache.listenerCount, "rejected NPHDS requests must not start the IPCache listener")
		})
	}
}

func TestADSKnownNodeEmptyStateAndReconnect(t *testing.T) {
	server := newTestADSServer(t, hivetest.Logger(t), nil, nil, xdsServerConfig{}, nil, nil)
	client := newTestADSClient(t, server)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.StreamAggregatedResources(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
		Node: &core.Node{Id: localNodeID}, TypeUrl: ListenerTypeURL, VersionInfo: "stale-version",
	}))
	empty, err := stream.Recv()
	require.NoError(t, err)
	require.Empty(t, empty.GetResources())
	require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
		// A subsequent request can omit Node; go-control-plane retains it.
		TypeUrl: ListenerTypeURL, VersionInfo: empty.GetVersionInfo(), ResponseNonce: empty.GetNonce(),
	}))
	resources := xds.NewResources()
	resources.Listeners["listener"] = &listener.Listener{Name: "listener"}
	require.NoError(t, server.UpsertEnvoyResources(t.Context(), resources, nil))
	added, err := stream.Recv()
	require.NoError(t, err)
	require.Len(t, added.GetResources(), 1)
	require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
		TypeUrl: ListenerTypeURL, VersionInfo: added.GetVersionInfo(), ResponseNonce: added.GetNonce(),
	}))
	require.NoError(t, server.DeleteEnvoyResources(t.Context(), resources, nil))
	removed, err := stream.Recv()
	require.NoError(t, err)
	require.Empty(t, removed.GetResources())
	cancel()

	ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	stream, err = client.StreamAggregatedResources(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
		Node: &core.Node{Id: localNodeID}, TypeUrl: ListenerTypeURL, VersionInfo: added.GetVersionInfo(),
	}))
	reconnected, err := stream.Recv()
	require.NoError(t, err)
	require.Empty(t, reconnected.GetResources(), "the empty local node remains known across disconnects")
}

func TestDeltaADSIncrementalACKAndNACKRollback(t *testing.T) {
	server := newTestADSServer(t, hivetest.Logger(t), nil, nil, xdsServerConfig{
		envoyXDSMode: config.EnvoyXDSModeDeltaADS,
	}, nil, nil)
	client := newTestADSClient(t, server)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	baseline := &listener.Listener{Name: "listener-a"}
	unchanged := &listener.Listener{Name: "listener-b"}
	marker := &envoy_config_cluster.Cluster{Name: "ack-marker"}
	require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, typeurl.Listener, baseline.Name, baseline, nil, nil))
	require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, typeurl.Listener, unchanged.Name, unchanged, nil, nil))
	require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, typeurl.Cluster, marker.Name, marker, nil, nil))

	stream, err := client.DeltaAggregatedResources(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
		Node: &core.Node{Id: localNodeID}, TypeUrl: ListenerTypeURL,
	}))
	initial, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, ListenerTypeURL, initial.GetTypeUrl())
	require.ElementsMatch(t, []string{baseline.Name, unchanged.Name}, deltaResponseResourceNames(initial))
	require.Empty(t, initial.GetRemovedResources())

	// ACK the initial LDS state. The following CDS request is an ordered marker
	// proving that the ACK has been processed before the update is applied.
	require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
		TypeUrl: ListenerTypeURL, ResponseNonce: initial.GetNonce(),
	}))
	require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: ClusterTypeURL}))
	markerResponse, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, ClusterTypeURL, markerResponse.GetTypeUrl())
	require.Equal(t, []string{marker.Name}, deltaResponseResourceNames(markerResponse))

	updated := &listener.Listener{
		Name: baseline.Name, TrafficDirection: core.TrafficDirection_OUTBOUND,
	}
	wg := completion.NewWaitGroup(ctx)
	done := waitForADSCompletion(t, wg)
	callbackResult := make(chan error, 1)
	require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, typeurl.Listener, updated.Name, updated, wg,
		func(err error) { callbackResult <- err }))

	updateResponse, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, ListenerTypeURL, updateResponse.GetTypeUrl())
	require.Equal(t, []string{updated.Name}, deltaResponseResourceNames(updateResponse),
		"Delta ADS must not resend an unchanged listener")
	require.True(t, proto.Equal(updated, deltaResponseListener(t, updateResponse)))
	requireADSCompletionPending(t, done)

	require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
		TypeUrl:       ListenerTypeURL,
		ResponseNonce: updateResponse.GetNonce(),
		ErrorDetail:   &statuspb.Status{Message: "rejected listener"},
	}))
	reverted, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, []string{baseline.Name}, deltaResponseResourceNames(reverted))
	require.True(t, proto.Equal(baseline, deltaResponseListener(t, reverted)))
	require.ErrorContains(t, <-done, "rejected listener")
	require.ErrorContains(t, <-callbackResult, "rejected listener")

	cached, ok := server.cache.GetResource(localNodeID, typeurl.Listener, baseline.Name).(*listener.Listener)
	require.True(t, ok)
	require.True(t, proto.Equal(baseline, cached), "a Delta NACK must restore the accepted resource")
}

func TestDeltaADSRemovalNACKRestoresResource(t *testing.T) {
	for _, test := range []struct {
		name     string
		typeURL  typeurl.Index
		resource proto.Message
	}{
		{
			name:     "endpoint",
			typeURL:  typeurl.Endpoint,
			resource: &endpoint.ClusterLoadAssignment{ClusterName: "resource"},
		},
		{
			name:     "route",
			typeURL:  typeurl.Route,
			resource: &route.RouteConfiguration{Name: "resource"},
		},
		{
			name:     "secret",
			typeURL:  typeurl.Secret,
			resource: &tls.Secret{Name: "resource"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestADSServer(t, hivetest.Logger(t), nil, nil, xdsServerConfig{
				envoyXDSMode: config.EnvoyXDSModeDeltaADS,
			}, nil, nil)
			client := newTestADSClient(t, server)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			const resourceName = "resource"
			marker := &envoy_config_cluster.Cluster{Name: "ack-marker"}
			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, resourceName, test.resource, nil, nil))
			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, typeurl.Cluster, marker.Name, marker, nil, nil))

			stream, err := client.DeltaAggregatedResources(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
				Node:                   &core.Node{Id: localNodeID},
				TypeUrl:                test.typeURL.URL(),
				ResourceNamesSubscribe: []string{resourceName},
			}))
			initial, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, []string{resourceName}, deltaResponseResourceNames(initial))

			require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
				TypeUrl: test.typeURL.URL(), ResponseNonce: initial.GetNonce(),
			}))
			require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: ClusterTypeURL}))
			markerResponse, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, []string{marker.Name}, deltaResponseResourceNames(markerResponse))

			wg := completion.NewWaitGroup(ctx)
			done := waitForADSCompletion(t, wg)
			callbackResult := make(chan error, 1)
			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, resourceName, nil, wg,
				func(err error) { callbackResult <- err }))
			removed, err := stream.Recv()
			require.NoError(t, err)
			require.Empty(t, removed.GetResources())
			require.Equal(t, []string{resourceName}, removed.GetRemovedResources())

			require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
				TypeUrl:       test.typeURL.URL(),
				ResponseNonce: removed.GetNonce(),
				ErrorDetail:   &statuspb.Status{Message: "rejected removal"},
			}))
			restored, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, []string{resourceName}, deltaResponseResourceNames(restored))
			require.Empty(t, restored.GetRemovedResources())
			restoredResource, err := restored.GetResources()[0].GetResource().UnmarshalNew()
			require.NoError(t, err)
			require.True(t, proto.Equal(test.resource, restoredResource))
			require.ErrorContains(t, <-done, "rejected removal")
			require.ErrorContains(t, <-callbackResult, "rejected removal")
			require.True(t, proto.Equal(test.resource, server.cache.GetResource(localNodeID, test.typeURL, resourceName)))
		})
	}
}

func TestDeltaADSRejectsUnknownNodes(t *testing.T) {
	server := newTestADSServer(t, hivetest.Logger(t), nil, nil, xdsServerConfig{
		envoyXDSMode: config.EnvoyXDSModeDeltaADS,
	}, nil, nil)
	client := newTestADSClient(t, server)
	for _, test := range []struct {
		name string
		node *core.Node
		code codes.Code
	}{
		{"unknown", &core.Node{Id: "unknown-node"}, codes.NotFound},
		{"empty", &core.Node{}, codes.InvalidArgument},
		{"missing", nil, codes.InvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			stream, err := client.DeltaAggregatedResources(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&discovery.DeltaDiscoveryRequest{
				Node: test.node, TypeUrl: ListenerTypeURL,
			}))
			_, err = stream.Recv()
			require.Equal(t, test.code, status.Code(err))
		})
	}
}

func deltaResponseResourceNames(response *discovery.DeltaDiscoveryResponse) []string {
	names := make([]string, 0, len(response.GetResources()))
	for _, resource := range response.GetResources() {
		names = append(names, resource.GetName())
	}
	return names
}

func deltaResponseListener(t *testing.T, response *discovery.DeltaDiscoveryResponse) *listener.Listener {
	t.Helper()
	require.Len(t, response.GetResources(), 1)
	resource := &listener.Listener{}
	require.NoError(t, response.GetResources()[0].GetResource().UnmarshalTo(resource))
	return resource
}

func TestADSRecognizesInitializedNodes(t *testing.T) {
	const nodeID = "another-known-node"
	logger := hivetest.Logger(t)
	cache := xdsnew.NewCache(logger, xdsnew.WithNodeIDs(localNodeID, nodeID))
	server := newTestADSServerWithCache(t, cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	require.NoError(t, cache.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", &listener.Listener{Name: "listener"}, nil, nil))
	client := newTestADSClient(t, server)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	stream, err := client.StreamAggregatedResources(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery.DiscoveryRequest{Node: &core.Node{Id: nodeID}, TypeUrl: ListenerTypeURL}))
	response, err := stream.Recv()
	require.NoError(t, err)
	require.Len(t, response.GetResources(), 1, "initialized node state, not the local node ID, establishes a known node")
	var received listener.Listener
	require.NoError(t, response.GetResources()[0].UnmarshalTo(&received))
	require.Equal(t, "listener", received.GetName())
}

func TestADSGRPCServerStopsOnContextCancel(t *testing.T) {
	logger := hivetest.Logger(t)
	server := newTestADSServer(t, logger, nil, nil, xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		proxyGID:             os.Getgid(),
		policyRestoreTimeout: time.Second,
	}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.run(ctx)
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(server.socketPath)
		return err == nil
	}, time.Second, 10*time.Millisecond)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("ADS gRPC server did not stop after context cancellation")
	}

	_, err := os.Stat(server.socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}
