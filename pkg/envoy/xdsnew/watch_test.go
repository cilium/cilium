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

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
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
	c := newCache(logger, WithNodeIDs("node1"))
	const nodeID = "node1"
	listener := &envoy_config_listener.Listener{Name: "listener"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil))

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
	publication := &publicationSignalingCache{SnapshotCache: c.snapshotCache, started: make(chan struct{}, 1)}
	c.replaceSnapshotCache(t, publication)
	publicationDone := make(chan error, 1)
	go func() {
		publicationDone <- c.ApplyResource(context.Background(), nodeID, typeurl.Listener,
			updatedListener.Name, updatedListener, nil)
	}()
	<-publication.started

	accessDone := make(chan struct{})
	var accessErr error
	go func() {
		// Exercise both Cilium's lock and go-control-plane's lock while the
		// stream's response channel remains deliberately unconsumed.
		cluster := &envoy_config_cluster.Cluster{Name: "unrelated-cluster"}
		accessErr = c.ApplyResource(context.Background(), nodeID, typeurl.Cluster, cluster.Name, cluster, nil)
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

// watchCancellationGate pauses go-control-plane watch cancellation after Cilium
// removes the watch from its indexes. It forwards that watch's response last
// during publication, making the late-response ordering deterministic.
type watchCancellationGate struct {
	cache.SnapshotCache
	typeURL         string
	started         chan struct{}
	release         <-chan struct{}
	forwardResponse func()
}

func (c *watchCancellationGate) CreateWatch(request *cache.Request, subscription cache.Subscription, responses chan cache.Response) (func(), error) {
	if request.GetTypeUrl() != c.typeURL || request.GetResponseNonce() == "" {
		return c.SnapshotCache.CreateWatch(request, subscription, responses)
	}
	pending := make(chan cache.Response, 1)
	c.forwardResponse = func() {
		select {
		case response := <-pending:
			responses <- response
		default:
		}
	}
	cancel, err := c.SnapshotCache.CreateWatch(request, subscription, pending)
	if cancel == nil {
		return nil, err
	}
	return func() {
		close(c.started)
		<-c.release
		cancel()
	}, err
}

func (c *watchCancellationGate) SetSnapshot(ctx context.Context, nodeID string, snapshot cache.ResourceSnapshot) error {
	if err := c.SnapshotCache.SetSnapshot(ctx, nodeID, snapshot); err != nil {
		return err
	}
	if c.forwardResponse != nil {
		c.forwardResponse()
	}
	return nil
}

func TestCanceledWatchResponseReleasesRelay(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "sotw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const nodeID = "node1"
			options := []CacheOption{WithNodeIDs(nodeID)}
			c := newCache(slog.New(slog.DiscardHandler), options...)
			node := &envoy_config_core.Node{Id: nodeID}
			releaseContext, release := context.WithCancel(t.Context())
			t.Cleanup(release)
			gate := &watchCancellationGate{
				SnapshotCache: c.snapshotCache, typeURL: typeurl.Listener.URL(),
				started: make(chan struct{}), release: releaseContext.Done(),
			}
			c.replaceSnapshotCache(t, gate)
			resources := xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{"listener": {Name: "listener"}},
				Clusters:  map[string]*envoy_config_cluster.Cluster{"cluster": {Name: "cluster"}},
			}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: resources}, nil, typeurl.EmptySet))
			responses := make(chan cache.Response, 2)
			var cancels []func()
			for _, typeURL := range []typeurl.Index{typeurl.Listener, typeurl.Cluster} {
				var cancel func()
				request := &cache.Request{Node: node, TypeUrl: typeURL.URL()}
				require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
				subscription := stream.NewSotwSubscription(nil, true)
				initialResponses := make(chan cache.Response, 1)
				initialCancel, err := c.CreateWatch(request, subscription, initialResponses)
				require.NoError(t, err)
				t.Cleanup(initialCancel)
				initial := <-initialResponses
				subscription.SetReturnedResources(initial.GetReturnedResources())
				wire, err := initial.GetDiscoveryResponse()
				require.NoError(t, err)
				wire.Nonce = request.TypeUrl
				c.completionCbs.OnStreamResponse(initial.GetContext(), 1, request, wire)
				request = &cache.Request{Node: node, TypeUrl: request.TypeUrl, ResponseNonce: wire.Nonce, VersionInfo: wire.VersionInfo}
				require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(func() {
					release()
					cancel()
				})
				cancels = append(cancels, cancel)
			}
			canceled := make(chan struct{})
			go func() {
				cancels[0]()
				close(canceled)
			}()
			<-gate.started

			// go-control-plane can still queue LDS after Cilium stops tracking its
			// watch. Queue it after CDS, which retires the last tracked watch.
			resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener", TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND}
			resources.Clusters["cluster"] = &envoy_config_cluster.Cluster{Name: "cluster", AltStatName: "new"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: resources}, nil, typeurl.EmptySet))
			release()
			<-canceled
			cancels[1]()
			c.completionCbs.OnStreamClosed(1, node)
			require.Zero(t, c.GetStatusInfo(nodeID).GetNumWatches())
			require.Empty(t, c.watchRelays, "draining the canceled response must release the empty relay")
		})
	}
}

func TestSotWWatchCancellationSynchronizesResponseDelivery(t *testing.T) {
	tests := []struct {
		name                   string
		buffered               bool
		sibling                bool
		cancelBeforeCollection bool
		replace                bool
	}{
		{name: "blocked unbuffered channel send"},
		{name: "full buffered response channel", buffered: true},
		{name: "response queued behind a sibling", sibling: true},
		{name: "go-control-plane cancellation races publication", sibling: true, cancelBeforeCollection: true},
		{name: "replacement watch after cancellation", replace: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const nodeID = "node1"
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
			node := &envoy_config_core.Node{Id: nodeID}
			releaseContext, release := context.WithCancel(t.Context())
			t.Cleanup(release)
			var gate *watchCancellationGate
			if tt.cancelBeforeCollection {
				gate = &watchCancellationGate{
					SnapshotCache: c.snapshotCache, typeURL: typeurl.Secret.URL(),
					started: make(chan struct{}), release: releaseContext.Done(),
				}
				c.replaceSnapshotCache(t, gate)
			}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Secret, "a", testSecret("a", "old"), nil))
			if tt.sibling {
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster",
					&envoy_config_cluster.Cluster{Name: "cluster"}, nil))
			}
			var capacity int
			if tt.buffered {
				capacity = 1
			}
			responses := make(chan cache.Response, capacity)
			watch := func(typeURL typeurl.Index, name string) func() {
				t.Helper()
				request := &cache.Request{Node: node, TypeUrl: typeURL.URL(), ResourceNames: []string{name}}
				require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
				subscription := stream.NewSotwSubscription(request.ResourceNames, false)
				initialResponses := make(chan cache.Response, 1)
				initialCancel, err := c.CreateWatch(request, subscription, initialResponses)
				require.NoError(t, err)
				t.Cleanup(initialCancel)
				initial := <-initialResponses
				if tt.buffered {
					// Keep the stream's buffered response channel full.
					responses <- initial
				}
				subscription.SetReturnedResources(initial.GetReturnedResources())
				wire, err := initial.GetDiscoveryResponse()
				require.NoError(t, err)
				wire.Nonce = name
				c.completionCbs.OnStreamResponse(initial.GetContext(), 1, request, wire)
				request = &cache.Request{
					Node: node, TypeUrl: request.TypeUrl, ResourceNames: request.ResourceNames,
					VersionInfo: wire.VersionInfo, ResponseNonce: wire.Nonce,
				}
				require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
				cancel, err := c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(func() {
					release()
					cancel()
				})
				return cancel
			}
			cancels := []func(){watch(typeurl.Secret, "a")}
			if tt.sibling {
				// CDS is sent first. Canceling the queued SDS response must
				// not wait for its sibling's blocked send.
				cancels = append(cancels, watch(typeurl.Cluster, "cluster"))
			}
			var canceledFirst chan struct{}
			if gate != nil {
				canceledFirst = make(chan struct{})
				go func() {
					cancels[0]()
					close(canceledFirst)
				}()
				<-gate.started
			}
			publication := &publicationSignalingCache{SnapshotCache: c.snapshotCache, started: make(chan struct{}, 1)}
			c.replaceSnapshotCache(t, publication)
			mutations := ResourceMutations{Upserted: xds.Resources{Secrets: map[string]*envoy_config_tls.Secret{
				"a": testSecret("a", "new"),
			}}}
			if tt.sibling {
				mutations.Upserted.Clusters = map[string]*envoy_config_cluster.Cluster{
					"cluster": {Name: "cluster", AltStatName: "new"},
				}
			}
			published := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				published <- c.ApplyResources(t.Context(), nodeID, mutations, nil, typeurl.EmptySet)
				close(finished)
			}()
			t.Cleanup(func() {
				release()
				// If an assertion fails, drain blocked sends before other
				// cleanup takes cache locks or releases the fixture.
				timeout := time.NewTimer(5 * time.Second)
				defer timeout.Stop()
				for {
					select {
					case <-finished:
						return
					case <-responses:
					case <-timeout.C:
						t.Error("snapshot publication did not finish during cleanup")
						return
					}
				}
			})
			<-publication.started
			// Wait until collection has released the cache lock.
			c.mutex.Lock()
			c.mutex.Unlock()
			canceled := make(chan struct{})
			go func() {
				remaining := cancels
				if gate != nil {
					release()
					<-canceledFirst
					remaining = remaining[1:]
				}
				for _, cancel := range remaining {
					cancel()
				}
				close(canceled)
			}()
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation must not wait for another watch's blocked send")
			}
			if tt.buffered {
				// SotW drains its ADS channel after cancellation before reusing
				// it. Freeing buffer space must not admit a late canceled send.
				<-responses
			}
			// go-control-plane leaves abandoned SotW response channels open,
			// unlike Delta, which closes its shared channel after cancellation.
			// Publication must finish without receiving the canceled response.
			select {
			case err := <-published:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation must unblock the SotW channel send")
			}
			if tt.buffered {
				require.Empty(t, responses, "cancellation must finish before a late send can reuse the freed buffer space")
			}
			if tt.replace {
				request := &cache.Request{Node: node, TypeUrl: typeurl.Secret.URL(), ResourceNames: []string{"a"}}
				require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
				replacementResponses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(request.ResourceNames, false), replacementResponses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				t.Cleanup(func() { c.completionCbs.OnStreamClosed(2, node) })
				cancels[0]()
				wire, err := (<-replacementResponses).GetDiscoveryResponse()
				require.NoError(t, err)
				require.Len(t, wire.Resources, 1)
				var secret envoy_config_tls.Secret
				require.NoError(t, wire.Resources[0].UnmarshalTo(&secret))
				require.True(t, xds.ResourceEqual(testSecret("a", "new"), &secret))
			}
			c.completionCbs.OnStreamClosed(1, node)
			require.Empty(t, c.watchRelays)
		})
	}
}

func TestCreateWatchImmediateResponseRetiresTracking(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
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
				c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
				const nodeID = "node1"
				node := &envoy_config_core.Node{Id: nodeID}
				update := func(listener *envoy_config_listener.Listener) *completion.WaitGroup {
					wg := completion.NewWaitGroup(t.Context())
					t.Cleanup(wg.Cancel)
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", listener, wg))
					return wg
				}
				var initial *envoy_config_listener.Listener
				var initialWG *completion.WaitGroup
				if !initialEmpty {
					initial = &envoy_config_listener.Listener{Name: "listener"}
					initialWG = update(initial)
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
				firstWG := update(&envoy_config_listener.Listener{
					Name: "listener", TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND,
				})
				latest := &envoy_config_listener.Listener{
					Name: "listener", TrafficDirection: envoy_config_core.TrafficDirection_INBOUND,
				}
				if repeatedVersion {
					latest = initial
				}
				secondWG := update(latest)
				response, err := oldResponse.GetDiscoveryResponse()
				require.NoError(t, err)
				response.Nonce = "old-response"
				c.completionCbs.OnStreamResponse(oldResponse.GetContext(), 1, request, response)
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: typeurl.Listener.URL(), VersionInfo: response.GetVersionInfo(), ResponseNonce: response.GetNonce(),
				}))
				if initialWG != nil {
					require.NoError(t, initialWG.Wait(), "the old response may ACK the original update")
				}
				// Both intervening generations must still await a newer response.
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
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1", "node2"))
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
	cancels[0]()
	require.Zero(t, c.GetStatusInfo("node1").GetNumWatches())
	cancels[0]()
	require.True(t, c.getNodeState("node1").openWatches.Empty())
	require.False(t, c.getNodeState("node2").openWatches.Empty())
	require.Equal(t, 1, c.watchRelays[responses].watches.Len())
	require.Equal(t, 1, c.GetStatusInfo("node2").GetNumWatches())
	cancels[1]()
	require.True(t, c.getNodeState("node1").openWatches.Empty())
	require.True(t, c.getNodeState("node2").openWatches.Empty())
	require.True(t, c.HasNode("node1"), "canceling watches must not forget a known node")
	require.True(t, c.HasNode("node2"))
	require.Empty(t, c.watchRelays)
}

func TestTrackedWatchesSharingRequestPointer(t *testing.T) {
	for _, watchCount := range []int{2, 3} {
		for _, action := range []string{"cancel", "respond"} {
			t.Run(fmt.Sprintf("watches-%d/%s", watchCount, action), func(t *testing.T) {
				c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
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
						listener.Name, listener, nil))
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
	t.Run("shared-relay", func(t *testing.T) {
		c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
		const nodeID = "node1"
		responses := make(chan cache.Response, 2)
		// Different TypeURLs can share one relay; both responses must survive
		// collection and retire their watches.
		for _, typeURL := range []typeurl.Index{typeurl.Listener, typeurl.Cluster} {
			request := &cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeURL.URL(),
			}
			subscription := stream.NewSotwSubscription(nil, true)
			cancel, err := c.CreateWatch(request, subscription, responses)
			require.NoError(t, err)
			t.Cleanup(cancel)
			initial := <-responses
			request.VersionInfo = initial.GetResponseVersion()
			subscription.SetReturnedResources(initial.GetReturnedResources())
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
			ResourceMutations{Upserted: resources}, nil, typeurl.EmptySet))
		var deliveredTypes []string
		for range 2 {
			response := <-responses
			deliveredTypes = append(deliveredTypes, response.GetRequest().GetTypeUrl())
		}
		expectedTypes := []string{typeurl.Cluster.URL(), typeurl.Listener.URL()}
		require.Equal(t, expectedTypes, deliveredTypes)
		require.Zero(t, c.GetStatusInfo(nodeID).GetNumWatches())
		require.True(t, c.getNodeState("node1").openWatches.Empty())
		require.Empty(t, c.watchRelays)
	})

}

type failingWatchCache struct {
	cache.SnapshotCache
}

func (c *failingWatchCache) CreateWatch(*cache.Request, cache.Subscription, chan cache.Response) (func(), error) {
	return nil, errors.New("watch creation failed")
}

func TestCreateWatchFailureRetiresTracking(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	c.replaceSnapshotCache(t, &failingWatchCache{SnapshotCache: c.snapshotCache})
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
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
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
