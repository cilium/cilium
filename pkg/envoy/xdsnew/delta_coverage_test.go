// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"strings"
	"testing"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// deltaCoverageStream uses the production cache watch and transport callbacks,
// retaining Delta's cumulative subscription across individual responses.
type deltaCoverageStream struct {
	cache    *cacheImpl
	sub      stream.Subscription
	nonce    uint64
	typeURL  typeurl.Index
	wildcard bool
	// Only explicit replies acknowledge a response; receive must not do so.
	requestNonce string
}

func (s *deltaCoverageStream) watch(t *testing.T, names ...string) chan cache.DeltaResponse {
	t.Helper()
	request := &cache.DeltaRequest{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: s.typeURL.URL(),
		ResourceNamesSubscribe: names, ResponseNonce: s.requestNonce,
	}
	require.NoError(t, s.cache.completionCbs.OnStreamDeltaRequest(1, request))
	if s.nonce == 0 {
		s.sub = stream.NewDeltaSubscription(names, nil, nil, s.wildcard)
	} else {
		s.sub.UpdateResourceSubscriptions(names, nil)
	}
	responses := make(chan cache.DeltaResponse, 1)
	cancel, err := s.cache.CreateDeltaWatch(request, &s.sub, responses)
	require.NoError(t, err)
	if cancel != nil {
		t.Cleanup(cancel)
	}
	return responses
}

func (s *deltaCoverageStream) receive(t *testing.T, names ...string) *discovery.DeltaDiscoveryResponse {
	t.Helper()
	select {
	case response := <-s.watch(t, names...):
		return s.deliver(t, response)
	default:
		t.Fatal("expected immediate Delta response")
		return nil
	}
}

func (s *deltaCoverageStream) deliver(t *testing.T, response cache.DeltaResponse) *discovery.DeltaDiscoveryResponse {
	t.Helper()
	out, err := response.GetDeltaDiscoveryResponse()
	require.NoError(t, err)
	s.nonce++
	out.Nonce = fmt.Sprint(s.nonce)
	s.cache.completionCbs.OnStreamDeltaResponse(1, response.GetDeltaRequest(), out)
	s.sub.SetReturnedResources(response.GetReturnedResources())
	return out
}

func (s *deltaCoverageStream) reply(t *testing.T, response *discovery.DeltaDiscoveryResponse, rejection string) {
	t.Helper()
	request := &cache.DeltaRequest{TypeUrl: response.TypeUrl, ResponseNonce: response.Nonce}
	if rejection != "" {
		request.ErrorDetail = &status.Status{Message: rejection}
	}
	require.NoError(t, s.cache.completionCbs.OnStreamDeltaRequest(1, request))
	s.requestNonce = response.Nonce
}

func TestDeltaNACKBatchCorrectsOnceAndSerializesCallers(t *testing.T) {
	c, handler := newGatedNACKCache(t, WithDeltaADS())
	t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
	baseline, a, b := testSecret("secret", "accepted"), testSecret("secret", "A"), testSecret("secret", "B")
	s := deltaCoverageStream{cache: c, typeURL: typeurl.Secret}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", s.typeURL, "secret", baseline, nil, nil))
	s.reply(t, s.receive(t, "secret"), "")
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", s.typeURL, "secret", a, nil, nil))
	responseA := s.receive(t)
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", s.typeURL, "secret", b, nil, nil))
	responseB := s.receive(t)
	before := c.getNodeState("coverage-node").resourceGeneration

	// An open watch can consume the correction. It must never receive
	// the intermediate A state while the two inverses are composed.
	request := &cache.DeltaRequest{Node: &core.Node{Id: "coverage-node"}, TypeUrl: s.typeURL.URL()}
	require.NoError(t, c.completionCbs.OnStreamDeltaRequest(1, request))
	responses := make(chan cache.DeltaResponse, 2)
	cancel, err := c.CreateDeltaWatch(request, &s.sub, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	gate := handler.gate(t, handler.beforeRevert)
	nacked := make(chan error, 1)
	go func() {
		nacked <- c.completionCbs.OnStreamDeltaRequest(1, &cache.DeltaRequest{
			TypeUrl: s.typeURL.URL(), ResponseNonce: responseB.Nonce,
			ErrorDetail: &status.Status{Message: "invalid secret"},
		})
	}()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Delta NACK did not enter cache recovery")
	}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	started, applied := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		applied <- c.ApplyResource(t.Context(), "coverage-node", s.typeURL, "secret", baseline, wg, func(err error) { done <- err })
	}()
	<-started
	select {
	case err := <-applied:
		t.Fatalf("cache caller interleaved with Delta recovery: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	closeChannelIfOpen(gate.release)
	require.NoError(t, <-nacked)
	require.NoError(t, <-applied)
	require.Equal(t, before+1, c.getNodeState("coverage-node").resourceGeneration)
	require.Same(t, baseline, c.GetResource("coverage-node", s.typeURL, "secret"))
	requireCoveragePending(t, done)
	s.reply(t, responseA, "")
	s.reply(t, responseB, "")
	requireCoveragePending(t, done)
	require.Len(t, responses, 1, "only the final corrected state may be published")
	correction := s.deliver(t, <-responses)
	require.Len(t, correction.Resources, 1)
	require.NotEqual(t, responseB.SystemVersionInfo, correction.SystemVersionInfo)
	s.reply(t, correction, "")
	require.NoError(t, <-done)
}

func TestDeltaCoverageExcludesUnchangedCumulativeResources(t *testing.T) {
	c := newCoverageCache(t, WithDeltaADS())
	t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
	a, aDone := upsertCoverageEndpoint(t, c, "a")
	_, bDone := upsertCoverageEndpoint(t, c, "b")
	s := deltaCoverageStream{cache: c}
	response := s.receive(t, "a")
	require.Len(t, response.Resources, 1)
	s.reply(t, response, "")
	require.NoError(t, <-aDone)
	requireCoveragePending(t, bDone)

	// A remains in the cumulative next-version map, but is not in B's response.
	// Rejecting B must neither reject A nor erase its resource-level acceptance.
	response = s.receive(t, "b")
	require.Len(t, response.Resources, 1)
	require.Equal(t, "b", response.Resources[0].Name)
	require.Len(t, s.sub.ReturnedResources(), 2)
	s.reply(t, response, "invalid b")
	require.ErrorContains(t, <-bDone, "invalid b")
	current := c.GetResource("coverage-node", typeurl.Endpoint, "a")
	require.Same(t, a, current)
	require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "b"))
	require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", a, true, callbacks.Revision{}))
}

func TestSotWAndDeltaResponseIdentitiesDoNotCollide(t *testing.T) {
	for _, deltaFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("delta-first=%t", deltaFirst), func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			a, aDone := upsertCoverageEndpoint(t, c, "a")
			sotw := coverageStream{cache: c, id: 1}
			delta := deltaCoverageStream{cache: c}
			var first, second *discovery.DiscoveryResponse
			var firstDelta, secondDelta *discovery.DeltaDiscoveryResponse
			if deltaFirst {
				firstDelta = delta.receive(t, "a")
			} else {
				first = sotw.receive(t, "a")
			}
			bDone := make(chan error, 1)
			b := &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", b, wg, func(err error) { bDone <- err }))
			if deltaFirst {
				second = sotw.receive(t, "a")
				require.Equal(t, firstDelta.Nonce, second.Nonce)
				delta.reply(t, firstDelta, "")
			} else {
				secondDelta = delta.receive(t, "a")
				require.Equal(t, first.Nonce, secondDelta.Nonce)
				sotw.reply(t, first, "", "a")
			}
			require.NoError(t, <-aDone)
			requireCoveragePending(t, bDone)
			require.Same(t, b, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
			if deltaFirst {
				sotw.reply(t, second, "invalid b", "a")
			} else {
				delta.reply(t, secondDelta, "invalid b")
			}
			require.ErrorContains(t, <-bDone, "invalid b")
			require.Same(t, a, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
		})
	}
}

func TestDeltaRejectsNonmatchingResponseNonces(t *testing.T) {
	for _, tt := range []struct {
		name      string
		nonce     string
		rejection string
	}{
		{name: "stale-ack", nonce: "1"},
		{name: "missing-ack"},
		{name: "stale-nack", nonce: "1", rejection: "stale rejection"},
		{name: "missing-nack", rejection: "missing nonce"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			_, done := upsertCoverageEndpoint(t, c, "a")
			s := deltaCoverageStream{cache: c}
			s.receive(t, "a")
			updated := &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", updated, nil, nil))
			current := s.receive(t)
			request := &discovery.DeltaDiscoveryRequest{TypeUrl: current.TypeUrl, ResponseNonce: tt.nonce}
			if tt.rejection != "" {
				request.ErrorDetail = &status.Status{Message: tt.rejection}
			}
			require.NoError(t, c.completionCbs.OnStreamDeltaRequest(1, request))
			requireCoveragePending(t, done)
			require.Same(t, updated, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
			s.reply(t, current, "")
			require.NoError(t, <-done)
		})
	}
}

func TestDelayedDeltaResponseDoesNotACKLaterSameTypeUpdates(t *testing.T) {
	c := newCoverageCache(t, WithDeltaADS())
	t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
	_, originalDone := upsertCoverageEndpoint(t, c, "a")
	s := deltaCoverageStream{cache: c}
	old := <-s.watch(t, "a")
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	updated := &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", updated, wg,
		func(err error) { done <- err }))
	// Encoding and the response callback are deliberately delayed until after
	// the newer revision is desired. The old ACK must retain its original scope.
	s.reply(t, s.deliver(t, old), "")
	require.NoError(t, <-originalDone)
	requireCoveragePending(t, done)
}

func TestDeltaRemovalCoverage(t *testing.T) {
	tests := []struct {
		name      string
		projected bool
		nack      bool
	}{
		{name: "explicit removal ACK"},
		{name: "empty assignment ACK", projected: true},
		{name: "empty assignment NACK", projected: true, nack: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			if tt.projected {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Cluster, "cluster",
					&cluster.Cluster{Name: "cluster", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
						EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{ServiceName: "a"}}, nil, nil))
			}
			original, aDone := upsertCoverageEndpoint(t, c, "a")
			s := deltaCoverageStream{cache: c}
			s.reply(t, s.receive(t, "a"), "")
			require.NoError(t, <-aDone)
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", nil, wg, nil))
			response := s.receive(t)
			if tt.projected {
				require.Len(t, response.Resources, 1)
				require.Equal(t, "a", response.Resources[0].Name)
				require.Empty(t, response.RemovedResources)
			} else {
				require.Empty(t, response.Resources)
				require.Equal(t, []string{"a"}, response.RemovedResources)
			}
			if tt.nack {
				s.reply(t, response, "invalid empty assignment")
				require.ErrorContains(t, wg.Wait(), "invalid empty assignment")
				require.Same(t, original, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
				correction := s.receive(t)
				require.Len(t, correction.Resources, 1)
				s.reply(t, correction, "")
			} else {
				s.reply(t, response, "")
				require.NoError(t, wg.Wait())
				require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
			}
		})
	}
}

func TestDeltaRollbackResendsRestoredResource(t *testing.T) {
	tests := []struct {
		name      string
		caller    bool
		removal   bool
		projected bool
	}{
		{name: "response NACK"},
		{name: "caller revert", caller: true},
		{name: "caller restores removal", caller: true, removal: true},
		{name: "caller restores synthesized CLA", caller: true, projected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			original := &endpoint.ClusterLoadAssignment{ClusterName: "a"}
			if tt.projected {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Cluster, "cluster",
					testEDSCluster("cluster", "a"), nil, nil))
			} else {
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "a", original, nil, nil))
			}
			s := deltaCoverageStream{cache: c}
			initial := s.receive(t, "a")
			s.reply(t, initial, "")
			var updated proto.Message
			if !tt.removal {
				updated = &endpoint.ClusterLoadAssignment{ClusterName: "a", Policy: &endpoint.ClusterLoadAssignment_Policy{}}
			}
			wg := completion.NewWaitGroup(t.Context())
			t.Cleanup(wg.Cancel)
			rollback, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Endpoint, "a", updated, wg, nil)
			require.NoError(t, err)
			t.Cleanup(rollback.Finalize)
			changed := s.receive(t)
			if tt.caller {
				s.reply(t, changed, "")
				require.NoError(t, wg.Wait())
				require.NoError(t, rollback.Revert())
			} else {
				s.reply(t, changed, "rejected endpoint")
				require.ErrorContains(t, wg.Wait(), "rejected endpoint")
			}
			// A content-identical restored value still needs a new Delta version
			// so a client retaining the old accepted version receives the correction.
			restored := s.receive(t)
			require.Len(t, restored.Resources, 1)
			require.Empty(t, restored.RemovedResources)
			require.Equal(t, "a", restored.Resources[0].Name)
			var decoded endpoint.ClusterLoadAssignment
			require.NoError(t, restored.Resources[0].Resource.UnmarshalTo(&decoded))
			require.True(t, proto.Equal(original, &decoded))
			require.NotEqual(t, initial.Resources[0].Version, restored.Resources[0].Version)
			if !tt.removal {
				require.NotEqual(t, changed.Resources[0].Version, restored.Resources[0].Version)
			}
			require.NotEqual(t, changed.SystemVersionInfo, restored.SystemVersionInfo)
			if tt.projected {
				require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "a"),
					"the synthesized CLA belongs only to the snapshot")
			} else {
				require.Same(t, original, c.GetResource("coverage-node", typeurl.Endpoint, "a"))
			}
			s.reply(t, restored, "")
		})
	}
}

func TestAcceptedStateSurvivesOtherModeStreamClose(t *testing.T) {
	for _, tt := range []struct {
		name       string
		closeDelta bool
	}{
		{name: "close SotW"},
		{name: "close Delta", closeDelta: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			a, done := upsertCoverageEndpoint(t, c, "a")
			sotw := coverageStream{cache: c, id: 1}
			delta := deltaCoverageStream{cache: c}
			sotwResponse, deltaResponse := sotw.receive(t, "a"), delta.receive(t, "a")
			sotw.reply(t, sotwResponse, "", "a")
			delta.reply(t, deltaResponse, "")
			require.NoError(t, <-done)
			if tt.closeDelta {
				c.completionCbs.OnDeltaStreamClosed(1, nil)
			} else {
				c.completionCbs.OnStreamClosed(1, nil)
			}
			require.True(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", a, true, callbacks.Revision{}),
				"closing the other protocol must preserve a live stream's resource acceptance")
			c.completionCbs.OnStreamClosed(1, nil)
			c.completionCbs.OnDeltaStreamClosed(1, nil)
			require.False(t, c.completionCbs.ResourceAccepted("coverage-node", typeurl.Endpoint, "a", a, true, callbacks.Revision{}),
				"the final stream close invalidates retained acceptance")
		})
	}
}

func TestDeltaResponseResolvesRollbackAfterOtherTypeUpdate(t *testing.T) {
	for _, tt := range []struct {
		name    string
		nack    bool
		wait    bool
		delayed bool
	}{
		{name: "ACK"},
		{name: "ACK with wait", wait: true},
		{name: "delayed ACK", delayed: true},
		{name: "delayed ACK with wait", delayed: true, wait: true},
		{name: "NACK", nack: true},
		{name: "NACK with wait", nack: true, wait: true},
		{name: "delayed NACK", delayed: true, nack: true},
		{name: "delayed NACK with wait", delayed: true, nack: true, wait: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			var wg *completion.WaitGroup
			if tt.wait {
				wg = completion.NewWaitGroup(t.Context())
				t.Cleanup(wg.Cancel)
			}
			policy := &cilium.NetworkPolicy{EndpointId: 2}
			secret := testSecret("secret", "initial")
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy",
				&cilium.NetworkPolicy{EndpointId: 1}, wg, nil))
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policy, wg, nil))
			// Advance the node's snapshot boundary beyond the policy's type version.
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Secret, "secret", secret, nil, nil))
			s := deltaCoverageStream{cache: c, typeURL: typeurl.NetworkPolicy, wildcard: true}
			old := <-s.watch(t)
			if tt.delayed {
				// Publish another type before encoding and reporting the older reply.
				secret = testSecret("secret", "updated")
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Secret, "secret", secret, nil, nil))
				other := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
				other.receive(t, "secret")
			}
			response := s.deliver(t, old)
			require.Equal(t, "e1:g2", response.SystemVersionInfo)
			rejection := ""
			if tt.nack {
				rejection = "rejected policy"
			}
			s.reply(t, response, rejection)
			if wg != nil {
				if tt.nack {
					require.ErrorContains(t, wg.Wait(), rejection)
				} else {
					require.NoError(t, wg.Wait())
				}
			}
			if tt.nack {
				require.Nil(t, c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy"))
			} else {
				// ACK must release its inverse even though a different type owns
				// the newer snapshot boundary. A later NACK restores this policy.
				require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy",
					&cilium.NetworkPolicy{EndpointId: 3}, nil, nil))
				s.reply(t, s.receive(t), "rejected next policy")
				require.Same(t, policy, c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy"))
			}
			require.Same(t, secret, c.GetResource("coverage-node", typeurl.Secret, "secret"))
		})
	}
}

func TestDeltaNoOpAndSupersededUpdateWaits(t *testing.T) {
	for _, tt := range []struct {
		name       string
		superseded bool
	}{
		{name: "no-op wait attaches to in-flight response"},
		{name: "NACK preserves newer update", superseded: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
			first := &cilium.NetworkPolicy{EndpointId: 1}
			wg1, wg2 := completion.NewWaitGroup(t.Context()), completion.NewWaitGroup(t.Context())
			t.Cleanup(wg1.Cancel)
			t.Cleanup(wg2.Cancel)
			done1, done2 := make(chan error, 1), make(chan error, 1)
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", first, wg1,
				func(err error) { done1 <- err }))
			s := deltaCoverageStream{cache: c, typeURL: typeurl.NetworkPolicy, wildcard: true}
			response := s.receive(t)
			next := proto.Clone(first).(*cilium.NetworkPolicy)
			if tt.superseded {
				next.EndpointId = 2
			}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", next, wg2,
				func(err error) { done2 <- err }))
			requireCoveragePending(t, done1)
			requireCoveragePending(t, done2)
			if tt.superseded {
				s.reply(t, response, "rejected older policy")
				require.ErrorContains(t, <-done1, "rejected older policy")
				requireCoveragePending(t, done2)
				require.Same(t, next, c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy"))
				s.reply(t, s.receive(t), "")
			} else {
				s.reply(t, response, "")
				require.NoError(t, <-done1)
			}
			require.NoError(t, <-done2)
			require.NoError(t, wg2.Wait())
			require.Zero(t, c.completionCbs.PendingCompletionCount())
		})
	}
}

func TestCreateDeltaWatchInactiveRequests(t *testing.T) {
	for _, tt := range []struct {
		name    string
		request *cache.DeltaRequest
		wantErr string
	}{
		{name: "nil request", wantErr: "nil Delta xDS request"},
		{name: "unknown node", request: &cache.DeltaRequest{
			Node: &core.Node{Id: "unknown"}, TypeUrl: typeurl.Secret.URL(),
		}, wantErr: "unknown xDS node"},
		{name: "empty named subscription", request: &cache.DeltaRequest{
			Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Secret.URL(),
		}},
		{name: "unsupported type", request: &cache.DeltaRequest{
			Node: &core.Node{Id: "coverage-node"}, TypeUrl: "type.googleapis.com/unknown.Resource",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCoverageCache(t, WithDeltaADS())
			responses := make(chan cache.DeltaResponse, 1)
			sub := stream.NewDeltaSubscription(nil, nil, nil, false)
			cancel, err := c.CreateDeltaWatch(tt.request, &sub, responses)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				t.Cleanup(cancel)
			}
			require.Empty(t, responses)
			_, err = c.GetSnapshot("coverage-node")
			require.Error(t, err, "inactive requests must not trigger publication")
		})
	}
}

func TestDeltaFirstWatchPublishesPendingChanges(t *testing.T) {
	c := newCoverageCache(t, WithDeltaADS())
	t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policy, nil, nil))
	_, err := c.GetSnapshot("coverage-node")
	require.Error(t, err)
	s := deltaCoverageStream{cache: c, typeURL: typeurl.NetworkPolicy, wildcard: true}
	first := s.receive(t)
	require.Len(t, first.Resources, 1)
	published := mustSnapshot(t, c, "coverage-node")
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 2}, nil, nil))
	current := mustSnapshot(t, c, "coverage-node")
	require.Same(t, published, current, "a consumed one-response watch cannot publish another mutation")
	next := s.receive(t)
	require.Len(t, next.Resources, 1)
	require.NotEqual(t, first.SystemVersionInfo, next.SystemVersionInfo)
}

func TestDeltaInitialVersionsAvoidMixedEpochs(t *testing.T) {
	c := newCoverageCache(t, WithDeltaADS())
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil))
	request := &cache.DeltaRequest{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.NetworkPolicy.URL(),
		InitialResourceVersions: map[string]string{"policy": "e1:g10", "other": "e3:g20", "legacy": "content-hash"},
	}
	sub := stream.NewDeltaSubscription(nil, nil, request.InitialResourceVersions, true)
	responses := make(chan cache.DeltaResponse, 1)
	cancel, err := c.CreateDeltaWatch(request, &sub, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	response, err := (<-responses).GetDeltaDiscoveryResponse()
	require.NoError(t, err)
	require.Len(t, response.Resources, 1)
	require.Equal(t, "e2:g1", response.Resources[0].Version)
	original := mustSnapshot(t, c, "coverage-node")

	// The next type's first request can collide with that epoch. Retain all
	// reported epochs so selecting its replacement also avoids the earlier set.
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Listener, "listener",
		&listener.Listener{Name: "listener"}, nil, nil))
	sotwResponses := make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(&cache.Request{
		Node: request.Node, TypeUrl: typeurl.Listener.URL(), VersionInfo: "e2:g30",
	}, stream.NewSotwSubscription(nil, true), sotwResponses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.True(t, strings.HasPrefix((<-sotwResponses).GetResponseVersion(), "e4:"))
	require.Equal(t, "e4:g1", mustSnapshot(t, c, "coverage-node").GetVersionMap(typeurl.NetworkPolicy.URL())["policy"])
	require.Equal(t, "e2:g1", original.GetVersionMap(typeurl.NetworkPolicy.URL())["policy"],
		"late epoch binding must not modify a previously published snapshot")
}

func TestDeltaWatchSendsOnlyChangedAndRemovedResources(t *testing.T) {
	c := newCoverageCache(t, WithDeltaADS())
	t.Cleanup(func() { c.completionCbs.OnDeltaStreamClosed(1, nil) })
	for i, name := range []string{"a", "b", "unchanged"} {
		require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, name,
			&cilium.NetworkPolicy{EndpointId: uint64(i + 1)}, nil, nil))
	}
	s := deltaCoverageStream{cache: c, typeURL: typeurl.NetworkPolicy, wildcard: true}
	initial := s.receive(t)
	require.Len(t, initial.Resources, 3)
	s.reply(t, initial, "")
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "a",
		&cilium.NetworkPolicy{EndpointId: 4}, nil, nil))
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "b", nil, nil, nil))
	response := s.receive(t)
	require.Len(t, response.Resources, 1)
	require.Equal(t, "a", response.Resources[0].Name)
	require.Equal(t, []string{"b"}, response.RemovedResources)
	s.reply(t, response, "")
}
