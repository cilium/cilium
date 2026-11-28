// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/hivetest"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/server/sotw/v3"
	envoy_server "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/container/set"
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

// Cache relays buffer SetSnapshot's synchronous responses until the cache locks
// can be released. The buffer assumes one watch per TypeURL per stream, however
// many resource names are subscribed. One response per name could fill the relay
// and block SetSnapshot before collection, even with a receiving gRPC client.
// Exercise the real go-control-plane ADS loop so an upstream change to watch
// replacement or response-channel ownership fails here. Investigate that contract
// before increasing buffer sizes; a larger fixed buffer would only move the limit.
func TestADSNamedSubscriptionsShareWatch(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "sotw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			cache := xdsnew.NewCache(logger, xdsnew.WithNodeIDs(localNodeID))
			server := newTestADSServerWithCache(t, cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
			client := newTestADSClient(t, server)
			// Bound blocked RPCs and publication on regression; successful runs
			// finish as soon as their responses arrive.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			// Exceed both the upstream stream buffers and Cilium's relay minimum.
			const resourceCount = 4 * max(int(cache_types.UnknownType), int(typeurl.Count))
			initial := xds.Resources{Endpoints: make(map[string]*endpoint.ClusterLoadAssignment, resourceCount)}
			updated := xds.Resources{Endpoints: make(map[string]*endpoint.ClusterLoadAssignment, resourceCount)}
			for i := range resourceCount {
				name := fmt.Sprintf("endpoint-%d", i)
				initial.Endpoints[name] = &endpoint.ClusterLoadAssignment{ClusterName: name}
				updated.Endpoints[name] = &endpoint.ClusterLoadAssignment{
					ClusterName: name, Endpoints: []*endpoint.LocalityLbEndpoints{{Priority: 1}},
				}
			}
			require.NoError(t, cache.ApplyResources(ctx, localNodeID, xdsnew.ResourceMutations{Upserted: initial}, nil, typeurl.Set{}))

			var nonce, version string
			var send func([]string) error
			var receive func() []*anypb.Any
			var watchCount func() int

			stream, err := client.StreamAggregatedResources(ctx)
			require.NoError(t, err)
			send = func(names []string) error {
				return stream.Send(&discovery.DiscoveryRequest{
					Node: &core.Node{Id: localNodeID}, TypeUrl: EndpointTypeURL,
					ResourceNames: names, VersionInfo: version, ResponseNonce: nonce,
				})
			}
			receive = func() []*anypb.Any {
				t.Helper()
				response, err := stream.Recv()
				require.NoError(t, err)
				require.Equal(t, EndpointTypeURL, response.GetTypeUrl())
				nonce, version = response.GetNonce(), response.GetVersionInfo()
				return response.GetResources()
			}
			watchCount = func() int { return cache.GetSnapshotCache().GetStatusInfo(localNodeID).GetNumWatches() }

			var names []string
			for i := range resourceCount {
				names = append(names, fmt.Sprintf("endpoint-%d", i))
				subscribed := names
				expected := len(names)

				require.NoError(t, send(subscribed))
				require.Len(t, receive(), expected)
			}
			require.NoError(t, send(names))
			// Send returning does not prove the server has processed the ACK.
			// Wait for its deferred watch before publishing; otherwise an immediate
			// CreateWatch response could bypass the publication path under scrutiny.
			require.Eventually(t, func() bool { return watchCount() == 1 }, 5*time.Second, time.Millisecond,
				"go-control-plane must replace the EDS watch when subscriptions change, rather than retain a watch per resource name")

			require.NoError(t, cache.ApplyResources(ctx, localNodeID, xdsnew.ResourceMutations{Upserted: updated}, nil, typeurl.Set{}),
				"publication must fit in the relay before responses can be collected; check watch replacement and response-channel ownership")
			resources := receive()
			require.Len(t, resources, resourceCount)
			var seen set.Set[string]
			for _, resource := range resources {
				var assignment endpoint.ClusterLoadAssignment
				require.NoError(t, resource.UnmarshalTo(&assignment))
				require.False(t, seen.Has(assignment.GetClusterName()), "each subscribed name must be delivered once")
				seen.Insert(assignment.GetClusterName())
				require.True(t, proto.Equal(updated.Endpoints[assignment.GetClusterName()], &assignment),
					"the response must contain the updated assignment for %q", assignment.GetClusterName())
			}
		})
	}
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
			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, "resource", test.initial, wg))
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
			require.Equal(t, 1, server.cache.GetCompletionCallbacks().PendingCompletionCount(), "an empty subscription must not complete the update")

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

			require.NoError(t, server.cache.ApplyResource(ctx, localNodeID, test.typeURL, "resource", test.updated, nil))
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

func TestADSWaitAfterNACK(t *testing.T) {
	const detail = "rejected listener"
	tests := []struct {
		name               string
		firstResponse      bool
		newer              bool
		resend             bool
		lateNACK           bool
		expectNACK         bool
		changeSubscription bool
		detail             string
		wildcard           []string
	}{
		{name: "retry initial rejection", firstResponse: true, detail: detail},
		{name: "NACK before registration", expectNACK: true, detail: detail},
		{name: "NACK without detail before registration", expectNACK: true, wildcard: []string{"*"}},
		{name: "newer version", newer: true, detail: detail},
		{name: "same version resent", resend: true, detail: detail},
		{name: "NACK from older stream after resend", lateNACK: true, detail: detail},
		{name: "same version on subscription change", changeSubscription: true, detail: detail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newTestADSServer(t, hivetest.Logger(t), nil, nil, xdsServerConfig{}, nil, nil)
				client := newTestADSClient(t, server)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				resources := xds.Resources{Listeners: map[string]*listener.Listener{"example": {Name: "example"}}}
				require.NoError(t, server.UpdateEnvoyResources(ctx, xds.Resources{}, resources, nil))

				type adsStream = discovery.AggregatedDiscoveryService_StreamAggregatedResourcesClient
				receive := func(stream adsStream, typeURL string) *discovery.DiscoveryResponse {
					response, err := stream.Recv()
					require.NoError(t, err)
					require.Equal(t, typeURL, response.GetTypeUrl())
					return response
				}
				open := func() (adsStream, context.CancelFunc, *discovery.DiscoveryResponse) {
					streamCtx, closeStream := context.WithCancel(ctx)
					t.Cleanup(closeStream)
					stream, err := client.StreamAggregatedResources(streamCtx)
					require.NoError(t, err)
					require.NoError(t, stream.Send(&discovery.DiscoveryRequest{
						Node:          &core.Node{Id: localNodeID},
						TypeUrl:       ListenerTypeURL,
						ResourceNames: tt.wildcard,
					}))
					response := receive(stream, ListenerTypeURL)
					require.NotEmpty(t, response.GetResources())
					return stream, closeStream, response
				}
				reply := func(stream adsStream, response *discovery.DiscoveryResponse, rejection *status.Status, names ...string) {
					if len(names) == 0 {
						names = tt.wildcard
					}
					request := &discovery.DiscoveryRequest{
						TypeUrl: ListenerTypeURL, ResponseNonce: response.GetNonce(), ResourceNames: names,
					}
					if rejection != nil {
						request.ErrorDetail = rejection.Proto()
					} else {
						request.VersionInfo = response.GetVersionInfo()
					}
					require.NoError(t, stream.Send(request))
					synctest.Wait()
				}

				stream, closeStream, rejected := open()
				if !tt.firstResponse {
					// ACK the initial update to settle its rollback. Envoy can
					// reject the same version after reconnecting, leaving the
					// cached value available for a later no-op update.
					reply(stream, rejected, nil)
					closeStream()
					acceptedVersion := rejected.GetVersionInfo()
					stream, closeStream, rejected = open()
					require.Equal(t, acceptedVersion, rejected.GetVersionInfo())
				}
				retryStream := stream
				var retry *discovery.DiscoveryResponse
				if tt.lateNACK {
					retryStream, _, retry = open()
					require.Equal(t, rejected.GetVersionInfo(), retry.GetVersionInfo())
				}
				var newNames []string
				if tt.changeSubscription {
					newNames = []string{"example"}
				}
				reply(stream, rejected, status.New(codes.InvalidArgument, tt.detail), newNames...)
				switch {
				case tt.firstResponse:
					corrective := receive(stream, ListenerTypeURL)
					require.NotEqual(t, rejected.GetVersionInfo(), corrective.GetVersionInfo())
					require.Empty(t, corrective.GetResources())
					reply(stream, corrective, nil)
				case tt.changeSubscription:
					retry = receive(stream, ListenerTypeURL)
					require.Equal(t, rejected.GetVersionInfo(), retry.GetVersionInfo())
				default:
					// The NACK has been processed. With no cache change, the
					// next response must be CDS, leaving the LDS watch open.
					require.NoError(t, stream.Send(&discovery.DiscoveryRequest{TypeUrl: ClusterTypeURL}))
					receive(stream, ClusterTypeURL)
				}
				if tt.resend {
					closeStream()
					retryStream, _, retry = open()
					require.Equal(t, rejected.GetVersionInfo(), retry.GetVersionInfo())
				}
				if tt.newer {
					more := xds.Resources{Listeners: map[string]*listener.Listener{"another": {Name: "another"}}}
					require.NoError(t, server.UpsertEnvoyResources(ctx, more, nil))
				}
				if tt.firstResponse {
					requireNoCachedResource(t, server.cache, localNodeID, ListenerTypeURL, "example")
				}

				wg := completion.NewWaitGroup(ctx)
				require.NoError(t, server.UpdateEnvoyResources(ctx, resources, resources, wg))
				if tt.expectNACK {
					require.EqualError(t, wg.Wait(), fmt.Sprintf("NACK from %s for %s version %s: %s",
						localNodeID, ListenerTypeURL, rejected.GetVersionInfo(), tt.detail))
					return
				}
				done := waitForADSCompletion(t, wg)
				synctest.Wait()
				requireADSCompletionPending(t, done)
				if retry == nil {
					retry = receive(retryStream, ListenerTypeURL)
					require.NotEqual(t, rejected.GetVersionInfo(), retry.GetVersionInfo())
				}
				reply(retryStream, retry, nil, newNames...)
				require.NoError(t, <-done)
			})
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

func TestADSRecognizesInitializedNodes(t *testing.T) {
	const nodeID = "another-known-node"
	logger := hivetest.Logger(t)
	cache := xdsnew.NewCache(logger, xdsnew.WithNodeIDs(localNodeID, nodeID))
	server := newTestADSServerWithCache(t, cache, logger, nil, nil, xdsServerConfig{}, nil, nil)
	require.NoError(t, cache.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", &listener.Listener{Name: "listener"}, nil))
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
