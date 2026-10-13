// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func TestPublishedUnsentRollbackDropsAddedThenRemovedEndpoint(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}

	endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "orphan"}
	cluster := &envoy_config_cluster.Cluster{Name: "unrelated-cluster"}
	err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Clusters:  map[string]*envoy_config_cluster.Cluster{"unrelated-cluster": cluster},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"orphan": endpoint},
	}}, nil, typeurl.Set{})
	require.NoError(t, err)

	clusterResponses := make(chan cache.Response, 1)
	clusterSubscription := stream.NewSotwSubscription(nil, true)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ClusterType,
	}, clusterSubscription, clusterResponses)
	require.NoError(t, err)
	response := <-clusterResponses
	clusterSubscription.SetReturnedResources(response.GetReturnedResources())
	cancel()
	acknowledgeResponse(t, c, 1, response, "initial-cluster")
	require.NotNil(t, c.getNodeState(nodeID).typeStates[typeurl.Endpoint].unsentRollback,
		"EDS rollback remains unsent without an EDS subscription")

	previous := mustSnapshot(t, c, nodeID)
	clusterResponses = make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ClusterType,
		VersionInfo: previous.GetVersion(envoy_resource.ClusterType),
	}, clusterSubscription, clusterResponses)
	require.NoError(t, err)
	err = c.ApplyResources(t.Context(), nodeID, ResourceMutations{
		Removed: xds.Resources{Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"orphan": endpoint}},
		Upserted: xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{
			"another-cluster": {Name: "another-cluster"},
		}},
	}, nil, typeurl.Set{})
	require.NoError(t, err)
	response = <-clusterResponses
	cancel()
	acknowledgeResponse(t, c, 1, response, "updated-cluster")

	state := c.getNodeState(nodeID)
	require.NotNil(t, state)
	state.requireNoUnsentRollbacks(t, "the net-zero EDS rollback must be discarded")
	require.Empty(t, state.resources[typeurl.Endpoint])
}

func TestPublishedUnsentRollbackCoalescesUntilResponse(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	const nodeID = "node1"
	node := &envoy_config_core.Node{Id: nodeID}

	baselineListener := &envoy_config_listener.Listener{Name: "listener-0"}
	baselinePolicy := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(ctx, nodeID, typeurl.NetworkPolicy, "policy", baselinePolicy, nil)
	require.NoError(t, err)
	err = c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": baselineListener},
	}}, nil, typeurl.Set{})
	require.NoError(t, err)

	listenerResponses := make(chan cache.Response, 1)
	listenerSubscription := stream.NewSotwSubscription(nil, true)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
	}, listenerSubscription, listenerResponses)
	require.NoError(t, err)
	initialResponse := <-listenerResponses
	listenerSubscription.SetReturnedResources(initialResponse.GetReturnedResources())
	cancel()
	acknowledgeResponse(t, c, 1, initialResponse, "initial-listener")
	baselineSnapshot := mustSnapshot(t, c, nodeID)
	acceptPublishedSnapshotVersions(t, c, 1, node, baselineSnapshot)
	c.getNodeState(nodeID).requireNoUnsentRollbacks(t)

	var policyRollback *responseRollback
	rollbackTarget := baselinePolicy
	var latestListener *envoy_config_listener.Listener
	for update := uint64(2); update <= 10; update++ {
		previousSnapshot := mustSnapshot(t, c, nodeID)
		listenerResponses = make(chan cache.Response, 1)
		cancel, err = c.CreateWatch(&cache.Request{
			Node: node, TypeUrl: envoy_resource.ListenerType,
			VersionInfo: previousSnapshot.GetVersion(envoy_resource.ListenerType),
		}, listenerSubscription, listenerResponses)
		require.NoError(t, err)

		var policy *cilium.NetworkPolicy
		if update != 5 && update != 9 {
			policy = &cilium.NetworkPolicy{EndpointId: update}
		}
		err = c.ApplyResource(ctx, nodeID, typeurl.NetworkPolicy, "policy", policy, nil)
		require.NoError(t, err)
		latestListener = &envoy_config_listener.Listener{Name: fmt.Sprintf("listener-%d", update)}
		err = c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
			Listeners: map[string]*envoy_config_listener.Listener{"listener": latestListener},
		}}, nil, typeurl.Set{})
		require.NoError(t, err)
		response := <-listenerResponses
		listenerSubscription.SetReturnedResources(response.GetReturnedResources())
		cancel()
		acknowledgeResponse(t, c, 1, response, fmt.Sprintf("listener-%d", update))

		current := c.getNodeState(nodeID).typeStates[typeurl.NetworkPolicy].unsentRollback
		if policy == nil {
			// Removal discards the old unsent chain. A later upsert starts
			// from absence, so its NACK must not restore the deleted baseline.
			require.Nil(t, current)
			policyRollback, rollbackTarget = nil, nil
			continue
		}
		require.NotNil(t, current)
		if policyRollback == nil {
			policyRollback = current
		} else {
			require.Same(t, policyRollback, current,
				"published NetworkPolicy updates must reuse one unsent rollback lifecycle")
		}
		require.Len(t, current.resources, 1)
		if rollbackTarget == nil {
			require.Nil(t, current.resources["policy"].previous.resource)
		} else {
			require.Same(t, rollbackTarget, current.resources["policy"].previous.resource)
		}
		require.Equal(t, typeurl.NetworkPolicy, current.typeURL)
	}
	latestSnapshot := mustSnapshot(t, c, nodeID)
	policyResponses := make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: typeurl.NetworkPolicyURL,
		VersionInfo: baselineSnapshot.GetVersion(typeurl.NetworkPolicyURL),
	}, stream.NewSotwSubscription(nil, true), policyResponses)
	require.NoError(t, err)
	policyResponse := <-policyResponses
	cancel()
	require.Equal(t, latestSnapshot.GetVersion(typeurl.NetworkPolicyURL), policyResponse.GetResponseVersion())
	c.getNodeState(nodeID).requireNoUnsentRollbacks(t,
		"producing the response must transfer rollback ownership to its ACK/NACK lifecycle")

	const policyNonce = "coalesced-policy"
	c.completionCbs.OnStreamResponse(policyResponse.GetContext(), 2, policyResponse.GetRequest(), &discovery.DiscoveryResponse{
		VersionInfo: policyResponse.GetResponseVersion(),
		TypeUrl:     typeurl.NetworkPolicyURL,
		Nonce:       policyNonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       typeurl.NetworkPolicyURL,
		VersionInfo:   baselineSnapshot.GetVersion(typeurl.NetworkPolicyURL),
		ResponseNonce: policyNonce,
		ErrorDetail:   &status.Status{Message: "rejected coalesced policy"},
	}))

	listener := c.GetResource(nodeID, typeurl.Listener, "listener")
	require.NotNil(t, listener)
	require.Same(t, latestListener, listener,
		"a NetworkPolicy NACK must not revert Listener updates from the same transaction")
	policy := c.GetResource(nodeID, typeurl.NetworkPolicy, "policy")
	require.Nil(t, policy, "NACK of an upsert after removal must not resurrect the deleted baseline")
}
func TestUnobservedSotWRemovalsDoNotAccumulateRollbackState(t *testing.T) {
	c := newCoverageCache(t)
	_, bDone := upsertCoverageEndpoint(t, c, "b")
	s := coverageStream{cache: c, id: 1}
	for update := range 20 {
		name := fmt.Sprintf("a-%d", update)
		_, done := upsertCoverageEndpoint(t, c, name)
		response := s.receive(t, name)
		s.reply(t, response, "", name)
		require.NoError(t, <-done)
		require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, name, nil, nil))
	}
	// B has never been requested. Its live inverse must not keep the unrelated
	// EDS removals above: omission does not convey their removal to Envoy.
	state := c.getNodeState("coverage-node")
	rollback := state.typeStates[typeurl.Endpoint].unsentRollback
	require.NotNil(t, rollback)
	require.Len(t, rollback.resources, 1)
	require.Contains(t, rollback.resources, "b")
	require.Len(t, state.resources[typeurl.Endpoint], 1)
	response := s.receive(t, "b")
	s.reply(t, response, "invalid b", "b")
	require.ErrorContains(t, <-bDone, "invalid b")
	for update := range 20 {
		require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, fmt.Sprintf("a-%d", update)), "NACK of B must not resurrect an unrelated removal")
	}
}
func TestUnsentRollbackHistoryIsBounded(t *testing.T) {
	for _, test := range []struct {
		name         string
		typeURL      typeurl.Index
		names        []string
		updates      int
		unrelated    bool
		coalescedABA bool
	}{
		{name: "without-unrelated-acks/single-policy", typeURL: typeurl.NetworkPolicy, names: []string{"policy"}, updates: 1000},
		{name: "without-unrelated-acks/bulk-endpoints", typeURL: typeurl.Endpoint, names: []string{"a", "b"}, updates: 100},
		{name: "unrelated/coalesced-policy-aba", typeURL: typeurl.NetworkPolicy, names: []string{"policy"}, updates: 10, unrelated: true, coalescedABA: true},
		{name: "unrelated/single-policy", typeURL: typeurl.NetworkPolicy, names: []string{"policy"}, updates: 1000, unrelated: true},
		{name: "unrelated/bulk-endpoints", typeURL: typeurl.Endpoint, names: []string{"a", "b"}, updates: 100, unrelated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newCoverageCache(t)
			lds := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
			for update := range test.updates {
				if test.typeURL == typeurl.NetworkPolicy {
					value := uint64(update + 1)
					if test.coalescedABA {
						value = 1
					}
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", test.typeURL, test.names[0],
						&cilium.NetworkPolicy{EndpointId: value}, nil))
					if test.coalescedABA {
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", test.typeURL, test.names[0], &cilium.NetworkPolicy{EndpointId: 2}, nil))
						require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", test.typeURL, test.names[0], &cilium.NetworkPolicy{EndpointId: value}, nil))
					}
				} else {
					endpoints := make(map[string]*envoy_config_endpoint.ClusterLoadAssignment)
					for _, name := range test.names {
						endpoints[name] = &envoy_config_endpoint.ClusterLoadAssignment{
							ClusterName: name,
							Policy: &envoy_config_endpoint.ClusterLoadAssignment_Policy{
								OverprovisioningFactor: wrapperspb.UInt32(uint32(update + 1)),
							},
						}
					}
					require.NoError(t, c.ApplyResources(t.Context(), "coverage-node",
						ResourceMutations{Upserted: xds.Resources{Endpoints: endpoints}}, nil, typeurl.Set{}))
				}
				if test.unrelated {
					// An unrelated update publishes the snapshot without exposing
					// the resources whose rollback history is being coalesced.
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "unrelated",
						&envoy_config_listener.Listener{Name: "unrelated", StatPrefix: fmt.Sprint(update)}, nil))
					lds.reply(t, lds.receive(t), "")
				}
			}
			// Retained state must depend on live names, not the number of API
			// transactions. Observable resource absence cannot detect this leak.
			state := c.getNodeState("coverage-node")
			if test.unrelated {
				unsent := state.typeStates[test.typeURL].unsentRollback
				require.NotNil(t, unsent)
				require.Len(t, unsent.resources, len(test.names))
				require.Equal(t, 1, state.rollbacks.responses.Len())
			} else {
				state.requireNoUnsentRollbacks(t)
				require.NotNil(t, state.pendingPublication)
				rollback, exists := state.pendingPublication.rollbacks.Get(test.typeURL)
				require.True(t, exists)
				require.Len(t, rollback, len(test.names))
				require.True(t, state.rollbacks.responses.Empty())
			}
			s := coverageStream{cache: c, id: 1, typeURL: test.typeURL.URL()}
			for i, name := range test.names {
				var names []string
				if test.typeURL == typeurl.Endpoint {
					names = []string{name}
				}
				s.reply(t, s.receive(t, names...), "invalid resource", names...)
				require.Nil(t, c.GetResource("coverage-node", test.typeURL, name))
				if i+1 < len(test.names) {
					require.NotNil(t, c.GetResource("coverage-node", test.typeURL, test.names[i+1]))
				}
			}
			require.True(t, state.rollbacks.responses.Empty())

		})
	}
}
