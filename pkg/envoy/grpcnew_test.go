// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/stretchr/testify/require"
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
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, envoy_server.NewServer(t.Context(), server.cache, server.newCallbacks(),
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
			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, "resource", test.initial, wg, nil))
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
			require.Equal(t, 1, server.cache.GetCompletionCallbacks().PendingCompletionCount())

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
			require.Zero(t, server.cache.GetCompletionCallbacks().PendingCompletionCount())
			require.Zero(t, server.cache.GetStatusInfo(localNodeID).GetNumWatches())

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
					require.Nil(t, server.cache.GetStatusInfo(test.node.GetId()), "rejected requests must not create watches")
					_, err = server.cache.GetSnapshot(test.node.GetId())
					require.Error(t, err, "rejected requests must not create snapshots")
				})
			}
			require.Zero(t, ipCache.listenerCount, "rejected NPHDS requests must not start the IPCache listener")
			require.Zero(t, server.cache.GetCompletionCallbacks().PendingCompletionCount())
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

func TestADSRecognizesInitializedNodes(t *testing.T) {
	const nodeID = "another-known-node"
	logger := hivetest.Logger(t)
	cache := xdsnew.NewCache(logger, false, xdsnew.WithNodeIDs(localNodeID, nodeID))
	server := newTestADSServerWithCache(t, cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	require.NoError(t, cache.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", &listener.Listener{Name: "listener"}, nil, nil))
	_, err := cache.GetSnapshot(nodeID)
	require.Error(t, err, "initial resources remain unpublished until a watch can consume them")
	client := newTestADSClient(t, server)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	stream, err := client.StreamAggregatedResources(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&discovery.DiscoveryRequest{Node: &core.Node{Id: nodeID}, TypeUrl: ListenerTypeURL}))
	response, err := stream.Recv()
	require.NoError(t, err)
	require.Len(t, response.GetResources(), 1, "initialized node state, not the local node ID, establishes a known node")
	stored, err := server.cache.GetSnapshot(nodeID)
	require.NoError(t, err)
	require.Equal(t, stored.GetVersion(ListenerTypeURL), response.GetVersionInfo())
	require.Contains(t, stored.GetResources(ListenerTypeURL), "listener", "serving a known node must publish its desired resources")
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
