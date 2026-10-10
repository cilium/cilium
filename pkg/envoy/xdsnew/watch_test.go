// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// publicationSignalingCache signals after cacheImpl has acquired its lock,
// just before go-control-plane starts delivering watch responses.
type publicationSignalingCache struct {
	cache.SnapshotCache
	started chan struct{}
}

func (c *publicationSignalingCache) SetSnapshot(ctx context.Context, nodeID string, snapshot cache.ResourceSnapshot) error {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.SnapshotCache.SetSnapshot(ctx, nodeID, snapshot)
}

func TestSnapshotResponseDeliveryDoesNotHoldCacheLocks(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	c := NewCache(logger, false, WithNodeIDs("node1")).(*cacheImpl)
	const nodeID = "node1"
	listener := &envoy_config_listener.Listener{Name: "listener"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))

	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Listener.URL(),
	}
	subscription := stream.NewSotwSubscription(nil, true)
	// Use the initial response to establish the client's version before opening
	// the watch whose response handoff will be deliberately blocked.
	initialResponses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, subscription, initialResponses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	initialResponse := <-initialResponses
	request.VersionInfo = initialResponse.GetResponseVersion()
	subscription.SetReturnedResources(initialResponse.GetReturnedResources())
	responses := make(chan cache.Response)
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.Equal(t, 1, c.GetStatusInfo(nodeID).GetNumWatches())

	updatedListener := &envoy_config_listener.Listener{
		Name: "listener", Address: &envoy_config_core.Address{},
	}
	publication := &publicationSignalingCache{SnapshotCache: c.SnapshotCache, started: make(chan struct{}, 1)}
	c.SnapshotCache = publication
	publicationDone := make(chan error, 1)
	go func() {
		publicationDone <- c.ApplyResource(context.Background(), nodeID, typeurl.Listener,
			updatedListener.Name, updatedListener, nil, nil)
	}()
	<-publication.started

	accessDone := make(chan struct{})
	var accessErr error
	go func() {
		// Exercise both Cilium's lock and go-control-plane's lock while the
		// stream's response channel remains deliberately unconsumed.
		cluster := &envoy_config_cluster.Cluster{Name: "unrelated-cluster"}
		accessErr = c.ApplyResource(context.Background(), nodeID, typeurl.Cluster, cluster.Name, cluster, nil, nil)
		c.GetResource(nodeID, typeurl.Listener, "listener")
		c.GetStatusInfo(nodeID).GetNumWatches()
		close(accessDone)
	}()
	t.Cleanup(func() {
		// Release the blocked handoff even when the regression assertion fails.
		select {
		case response := <-responses:
			require.Same(t, request, response.GetRequest())
			require.NotEqual(t, request.VersionInfo, response.GetResponseVersion())
			require.Contains(t, response.GetReturnedResources(), listener.Name)
		case <-time.After(5 * time.Second):
			t.Error("snapshot response was not delivered")
		}
		select {
		case err := <-publicationDone:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("snapshot publication did not finish")
		}
		select {
		case <-accessDone:
		case <-time.After(5 * time.Second):
			t.Error("cache access did not finish")
		}
	})

	select {
	case <-accessDone:
		require.NoError(t, accessErr)
		resource := c.GetResource(nodeID, typeurl.Listener, listener.Name)
		require.NotNil(t, resource)
		require.Same(t, updatedListener, resource)
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked response handoff must not hold either cache lock")
	}
}

func TestCreateWatchImmediateResponseRetiresTracking(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Listener.URL(),
	}
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	response := <-responses
	require.Same(t, request, response.GetRequest())
	require.True(t, c.getNodeState("node1").openWatches.Empty())
	require.Empty(t, c.watchRelays)
	require.Zero(t, c.GetStatusInfo("node1").GetNumWatches())
	// An already served watch has nothing left to cancel.
	cancel()
	cancel()
}

func TestDelayedImmediateResponseDoesNotACKLaterSameTypeUpdates(t *testing.T) {
	for _, initialEmpty := range []bool{false, true} {
		for _, repeatedVersion := range []bool{false, true} {
			t.Run(fmt.Sprintf("initial-empty=%t/repeated-version=%t", initialEmpty, repeatedVersion), func(t *testing.T) {
				c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				var completed []int
				update := func(id int, listener *envoy_config_listener.Listener) *completion.WaitGroup {
					wg := completion.NewWaitGroup(t.Context())
					t.Cleanup(wg.Cancel)
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", listener, wg,
						func(err error) {
							require.NoError(t, err)
							completed = append(completed, id)
						}))
					return wg
				}
				var initial *envoy_config_listener.Listener
				if !initialEmpty {
					initial = &envoy_config_listener.Listener{Name: "listener"}
					update(0, initial)
				}
				request := &cache.Request{Node: node, TypeUrl: typeurl.Listener.URL()}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				oldResponse := <-responses
				// Hold the immediate response before OnStreamResponse runs, just
				// as a busy stream can delay the cache-to-server handoff. Both
				// intervening updates use LDS, including an optional A-B-A case.
				firstWG := update(1, &envoy_config_listener.Listener{
					Name: "listener", TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND,
				})
				latest := &envoy_config_listener.Listener{
					Name: "listener", TrafficDirection: envoy_config_core.TrafficDirection_INBOUND,
				}
				if repeatedVersion {
					latest = initial
				}
				secondWG := update(2, latest)
				response, err := oldResponse.GetDiscoveryResponse()
				require.NoError(t, err)
				response.Nonce = "old-response"
				c.completionCbs.OnStreamResponse(oldResponse.GetContext(), 1, request, response)
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: typeurl.Listener.URL(), VersionInfo: response.GetVersionInfo(), ResponseNonce: response.GetNonce(),
				}))
				if initialEmpty {
					require.Empty(t, completed, "an ACK of the initial empty snapshot must not claim later generations")
				} else {
					require.Equal(t, []int{0}, completed, "the old response may ACK only the original update")
				}
				require.Equal(t, 2, c.completionCbs.PendingCompletionCount())

				// A fresh stream consumes the current snapshot, even when its
				// contents happen to have returned to the old content version.
				require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
				cancel, err = c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				currentResponse := <-responses
				response, err = currentResponse.GetDiscoveryResponse()
				require.NoError(t, err)
				response.Nonce = "current-response"
				c.completionCbs.OnStreamResponse(currentResponse.GetContext(), 2, request, response)
				require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: typeurl.Listener.URL(), VersionInfo: response.GetVersionInfo(), ResponseNonce: response.GetNonce(),
				}))
				require.NoError(t, firstWG.Wait())
				require.NoError(t, secondWG.Wait())
				require.Zero(t, c.completionCbs.PendingCompletionCount())
			})
		}
	}
}

func TestTrackedWatchRemovalPreservesOtherNodes(t *testing.T) {
	for _, clearSnapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("clear-snapshot=%t", clearSnapshot), func(t *testing.T) {
			c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1", "node2")).(*cacheImpl)
			responses := make(chan cache.Response, 2)
			var cancels []func()
			for _, nodeID := range []string{"node1", "node2"} {
				request := &cache.Request{
					Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Listener.URL(),
				}
				subscription := stream.NewSotwSubscription(nil, true)
				cancel, err := c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				response := <-responses
				subscription.SetReturnedResources(response.GetReturnedResources())
				request.VersionInfo = response.GetResponseVersion()
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				cancels = append(cancels, cancel)
			}
			require.False(t, c.getNodeState("node1").openWatches.Empty())
			require.False(t, c.getNodeState("node2").openWatches.Empty())
			require.Len(t, c.watchRelays, 1, "nodes sharing a response channel share its relay")
			if clearSnapshot {
				c.ClearSnapshot("node1")
				require.Nil(t, c.GetStatusInfo("node1"))
			} else {
				cancels[0]()
				require.Zero(t, c.GetStatusInfo("node1").GetNumWatches())
			}
			cancels[0]()
			require.True(t, c.getNodeState("node1").openWatches.Empty())
			require.False(t, c.getNodeState("node2").openWatches.Empty())
			require.Equal(t, 1, c.watchRelays[responses].watches.Len())
			require.Equal(t, 1, c.GetStatusInfo("node2").GetNumWatches())
			cancels[1]()
			require.True(t, c.getNodeState("node1").openWatches.Empty())
			require.True(t, c.getNodeState("node2").openWatches.Empty())
			require.True(t, c.HasNode("node1"), "canceling or clearing watches must not forget a known node")
			require.True(t, c.HasNode("node2"))
			require.Empty(t, c.watchRelays)
		})
	}
}

func TestTrackedWatchesSharingRequestPointer(t *testing.T) {
	for _, watchCount := range []int{2, 3} {
		for _, action := range []string{"cancel", "respond", "clear"} {
			t.Run(fmt.Sprintf("watches-%d/%s", watchCount, action), func(t *testing.T) {
				c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
				const nodeID = "node1"
				request := &cache.Request{
					Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.Listener.URL(),
				}
				responses := make(chan cache.Response, watchCount)
				subscription := stream.NewSotwSubscription(nil, true)
				// Consume the initial response so subsequent registrations wait
				// on the same version, rather than immediately retiring.
				cancel, err := c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				initial := <-responses
				request.VersionInfo = initial.GetResponseVersion()
				subscription.SetReturnedResources(initial.GetReturnedResources())
				var cancels []func()
				for range watchCount {
					cancel, err := c.CreateWatch(request, subscription, responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					cancels = append(cancels, cancel)
				}
				watches, exists := c.getNodeState(nodeID).openWatches.Get(typeurl.Listener)
				require.True(t, exists)
				require.Equal(t, watchCount, watches.Len())
				require.Equal(t, watchCount, c.watchRelays[responses].watches.Len())
				require.Equal(t, watchCount, c.GetStatusInfo(nodeID).GetNumWatches())
				for watch := range watches.Members() {
					require.Same(t, request, watch.request, "watch identity must not be the shared request pointer")
				}

				switch action {
				case "cancel":
					cancels[0]()
					cancels[0]()
					remaining, exists := c.getNodeState(nodeID).openWatches.Get(typeurl.Listener)
					require.True(t, exists)
					require.Equal(t, watchCount-1, remaining.Len())
					require.Equal(t, watchCount-1, c.watchRelays[responses].watches.Len())
					require.Equal(t, watchCount-1, c.GetStatusInfo(nodeID).GetNumWatches())
					for _, cancel := range cancels[1:] {
						cancel()
					}
				case "respond":
					listener := &envoy_config_listener.Listener{Name: "listener"}
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener,
						listener.Name, listener, nil, nil))
					updated, err := c.GetSnapshot(nodeID)
					require.NoError(t, err)
					for range watchCount {
						select {
						case response := <-responses:
							require.Same(t, request, response.GetRequest())
							require.Equal(t, updated.GetVersion(typeurl.Listener.URL()), response.GetResponseVersion())
						case <-time.After(time.Second):
							t.Fatal("each watch must receive its own response")
						}
					}
				case "clear":
					c.ClearSnapshot(nodeID)
					require.Nil(t, c.GetStatusInfo(nodeID))
				}
				require.True(t, c.getNodeState(nodeID).openWatches.Empty())
				require.Empty(t, c.watchRelays)

				if action == "cancel" {
					// Retained cancellation closures keep the old watches alive.
					// Reusing the request and response channel must still create an
					// independent watch which old cancellation calls cannot retire.
					cancel, err := c.CreateWatch(request, subscription, responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					for _, oldCancel := range cancels {
						oldCancel()
					}
					require.Equal(t, 1, c.GetStatusInfo(nodeID).GetNumWatches())
					cancel()
					require.True(t, c.getNodeState(nodeID).openWatches.Empty())
					require.Empty(t, c.watchRelays)
				}
			})
		}
	}
}

func TestSharedWatchRelayPreservesResponseOrder(t *testing.T) {
	for _, strictADS := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strictADS), func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
			c := NewCache(logger, strictADS, WithNodeIDs("node1")).(*cacheImpl)
			const nodeID = "node1"
			responses := make(chan cache.Response, 2)
			// Register in reverse dependency order. The relay must deliver CDS
			// before LDS in both strict and non-strict ADS.
			for _, typeURL := range []typeurl.Index{typeurl.Listener, typeurl.Cluster} {
				request := &cache.Request{
					Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeURL.URL(),
				}
				subscription := stream.NewSotwSubscription(nil, true)
				// Receive each type's initial response before echoing its version.
				// Borrowing another type's version would look like an old agent
				// epoch on this type's first request and force epoch rotation.
				cancel, err := c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				initialResponse := <-responses
				request.VersionInfo = initialResponse.GetResponseVersion()
				subscription.SetReturnedResources(initialResponse.GetReturnedResources())
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
			}
			require.Len(t, c.watchRelays, 1)
			require.Equal(t, 2, c.watchRelays[responses].watches.Len())

			resources := xds.NewResources()
			resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
			resources.Clusters["cluster"] = &envoy_config_cluster.Cluster{Name: "cluster"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID,
				ResourceMutations{Upserted: resources}, nil, TypeURLCallbacks{}))
			var deliveredTypes []string
			for range 2 {
				response := <-responses
				deliveredTypes = append(deliveredTypes, response.GetRequest().GetTypeUrl())
			}
			expectedTypes := []string{typeurl.Cluster.URL(), typeurl.Listener.URL()}
			require.Equal(t, expectedTypes, deliveredTypes)
			require.Zero(t, c.GetStatusInfo(nodeID).GetNumWatches())
			require.True(t, c.getNodeState(nodeID).openWatches.Empty())
			require.Empty(t, c.watchRelays)
		})
	}
}

type failingWatchCache struct {
	cache.SnapshotCache
}

func (c *failingWatchCache) CreateWatch(*cache.Request, cache.Subscription, chan cache.Response) (func(), error) {
	return nil, errors.New("watch creation failed")
}

func TestCreateWatchFailureRetiresTracking(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
	c.SnapshotCache = &failingWatchCache{SnapshotCache: c.SnapshotCache}
	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Listener.URL(),
	}
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
	require.ErrorContains(t, err, "watch creation failed")
	require.Nil(t, cancel)
	require.True(t, c.getNodeState("node1").openWatches.Empty())
	require.Empty(t, c.watchRelays)
}

func BenchmarkTrackedWatchLifecycle(b *testing.B) {
	for _, watchCount := range []int{1, 2, 8} {
		b.Run(fmt.Sprintf("watches-%d", watchCount), func(b *testing.B) {
			c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("node1")).(*cacheImpl)
			request := &cache.Request{
				Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Listener.URL(),
			}
			responses := make(chan cache.Response, watchCount)
			subscription := stream.NewSotwSubscription(nil, true)
			cancel, err := c.CreateWatch(request, subscription, responses)
			if err != nil {
				b.Fatal(err)
			}
			initial := <-responses
			request.VersionInfo = initial.GetResponseVersion()
			subscription.SetReturnedResources(initial.GetReturnedResources())
			cancel()
			cancels := make([]func(), watchCount)

			// The current version makes every CreateWatch deferred. Measure the
			// production registration/cancellation paths without snapshot creation
			// or a simulated client, including multi-watch representation changes.
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for i := range watchCount {
					cancels[i], err = c.CreateWatch(request, subscription, responses)
					if err != nil {
						b.Fatal(err)
					}
				}
				for _, cancel := range cancels {
					cancel()
				}
			}
		})
	}
}
