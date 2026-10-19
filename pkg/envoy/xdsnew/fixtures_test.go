// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/completion"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// newTestCache initializes the immutable set of supported nodes.
func newTestCache(t testing.TB, nodeIDs ...string) *cacheImpl {
	t.Helper()
	return newCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeIDs...))
}

// Each invocation returns fresh protobufs so fixture mutations cannot leak
// between test cases.
func testResourceTypes() []struct {
	typeURL  typeurl.Index
	resource proto.Message
	removed  proto.Message
} {
	return []struct {
		typeURL  typeurl.Index
		resource proto.Message
		removed  proto.Message
	}{
		{typeurl.Endpoint, &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "resource"}, (*envoy_config_endpoint.ClusterLoadAssignment)(nil)},
		{typeurl.Cluster, &envoy_config_cluster.Cluster{Name: "resource"}, (*envoy_config_cluster.Cluster)(nil)},
		{typeurl.Route, &envoy_config_route.RouteConfiguration{Name: "resource"}, (*envoy_config_route.RouteConfiguration)(nil)},
		{typeurl.Listener, &envoy_config_listener.Listener{Name: "resource"}, (*envoy_config_listener.Listener)(nil)},
		{typeurl.Secret, &envoy_config_tls.Secret{Name: "resource"}, (*envoy_config_tls.Secret)(nil)},
		{typeurl.NetworkPolicy, &cilium.NetworkPolicy{EndpointId: 1}, (*cilium.NetworkPolicy)(nil)},
		{typeurl.NetworkPolicyHosts, &cilium.NetworkPolicyHosts{Policy: 1}, (*cilium.NetworkPolicyHosts)(nil)},
	}
}

func newTestNPDSListenerObserver(nodeID string) *testNPDSListenerObserver {
	return &testNPDSListenerObserver{
		nodeID: nodeID,
		matches: func(listener *envoy_config_listener.Listener) bool {
			return strings.HasPrefix(listener.GetName(), "npds-")
		},
	}
}

func testSecret(name, contents string) *envoy_config_tls.Secret {
	return &envoy_config_tls.Secret{Name: name, Type: &envoy_config_tls.Secret_GenericSecret{
		GenericSecret: &envoy_config_tls.GenericSecret{Secret: &envoy_config_core.DataSource{
			Specifier: &envoy_config_core.DataSource_InlineString{InlineString: contents},
		}},
	}}
}

func testRDSListener(t *testing.T, name, route string) *envoy_config_listener.Listener {
	t.Helper()
	return &envoy_config_listener.Listener{
		Name: name,
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t,
					&envoy_config_http.HttpConnectionManager{RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
						Rds: &envoy_config_http.Rds{RouteConfigName: route},
					}})},
			}},
		}},
	}
}

func testEDSCluster(name, endpoint string) *envoy_config_cluster.Cluster {
	return &envoy_config_cluster.Cluster{
		Name:                 name,
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: endpoint},
	}
}

type mockSnapshotCache struct {
	snapshots                map[string]cache.ResourceSnapshot
	setSnapshotErr           error
	storeSnapshotBeforeError bool

	// Call tracking
	setSnapshotCalls []context.Context
	getSnapshotCalls []string
	createWatchCalls int
}

func newMockSnapshotCache() *mockSnapshotCache {
	return &mockSnapshotCache{
		snapshots: make(map[string]cache.ResourceSnapshot),
	}
}

func (m *mockSnapshotCache) SetSnapshot(ctx context.Context, node string, snapshot cache.ResourceSnapshot) error {
	m.setSnapshotCalls = append(m.setSnapshotCalls, ctx)
	if m.storeSnapshotBeforeError {
		m.snapshots[node] = snapshot
	}
	if m.setSnapshotErr != nil {
		return m.setSnapshotErr
	}
	m.snapshots[node] = snapshot
	return nil
}

func (m *mockSnapshotCache) GetSnapshot(node string) (cache.ResourceSnapshot, error) {
	m.getSnapshotCalls = append(m.getSnapshotCalls, node)
	snap, ok := m.snapshots[node]
	if !ok {
		return nil, fmt.Errorf("no snapshot found for node %s", node)
	}
	return snap, nil
}

func (*mockSnapshotCache) ClearSnapshot(string) {
	panic("unexpected ClearSnapshot call")
}

func (m *mockSnapshotCache) GetStatusInfo(node string) cache.StatusInfo {
	return nil
}

func (m *mockSnapshotCache) GetStatusKeys() []string {
	keys := make([]string, 0, len(m.snapshots))
	for k := range m.snapshots {
		keys = append(keys, k)
	}
	return keys
}

func (m *mockSnapshotCache) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	m.createWatchCalls++
	return func() {}, nil
}

func (m *mockSnapshotCache) CreateDeltaWatch(request *cache.DeltaRequest, sub cache.Subscription, respChan chan cache.DeltaResponse) (cancel func(), err error) {
	return func() {}, nil
}

func (m *mockSnapshotCache) Fetch(ctx context.Context, request *cache.Request) (cache.Response, error) {
	return nil, fmt.Errorf("not implemented")
}

// replaceSnapshotCache temporarily replaces the underlying go-control-plane cache,
// preserving Cilium's wrapper for normal cache operations. Swap only between
// backend calls: some read-only delegates do not take the Cilium cache lock.
// The returned restore function permits an early retry using the original
// backend; cleanup then becomes a no-op. Never install c.GetSnapshotCache(),
// which returns the wrapper itself and would introduce recursion.
func (c *cacheImpl) replaceSnapshotCache(t testing.TB, backend cache.SnapshotCache) (restore func()) {
	t.Helper()
	c.mutex.Lock()
	previous := c.snapshotCache
	c.snapshotCache = backend
	c.mutex.Unlock()
	restore = func() {
		c.mutex.Lock()
		if previous != nil {
			c.snapshotCache = previous
			previous = nil
		}
		c.mutex.Unlock()
	}
	t.Cleanup(restore)
	return restore
}

func newInitializedTestCache(t testing.TB, mock *mockSnapshotCache) *cacheImpl {
	t.Helper()
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), WithNodeIDs("node1"))
	c.replaceSnapshotCache(t, mock)
	return c
}

func mustAny(t *testing.T, msg proto.Message) *anypb.Any {
	t.Helper()
	any, err := anypb.New(msg)
	require.NoError(t, err)
	return any
}

// publishedResponseForTest obtains a real, filtered go-control-plane response
// for tests which drive stream callbacks explicitly. Freeze its cache inverse
// exactly as watch collection does, rather than pretending that a TypeURL
// version alone proves delivery of all resources.
func publishedResponseForTest(t *testing.T, c *cacheImpl, node *envoy_config_core.Node, index typeurl.Index) cache.Response {
	t.Helper()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	snapshot := mustSnapshot(t, c, node.Id)
	responder := c.snapshotCache
	if _, mocked := responder.(*mockSnapshotCache); mocked {
		// Publication-failure tests intentionally replace the transport cache.
		responder = cache.NewSnapshotCache(false, cache.IDHash{}, nil)
		require.NoError(t, responder.SetSnapshot(t.Context(), node.Id, snapshot))
	}
	response, err := responder.Fetch(t.Context(), &cache.Request{Node: node, TypeUrl: index.URL()})
	require.NoError(t, err)
	response = callbacks.WithResponseCoverage(response, c.getNodeState(node.Id).snapshotGeneration, snapshot)
	state := c.getNodeState(node.Id)
	// Fetch bypasses CreateWatch. This fixture delivers the current snapshot,
	// so a later version echo belongs to this agent's negotiated namespace.
	state.commitEpochNegotiation(index)
	state.rollbacks.claimResponseLocked(c, state, index, response)
	return response
}

func ackNetworkPolicyVersion(t *testing.T, c *cacheImpl, nodeID, version string) {
	t.Helper()
	node := &envoy_config_core.Node{Id: nodeID}
	response := publishedResponseForTest(t, c, node, typeurl.NetworkPolicy)
	require.Equal(t, version, response.GetResponseVersion())
	acknowledgeResponse(t, c, 1, response, "policy-ack")
}

func acknowledgeResponse(t *testing.T, c *cacheImpl, streamID int64, response cache.Response, nonce string) {
	t.Helper()
	request := response.GetRequest()
	c.completionCbs.OnStreamResponse(response.GetContext(), streamID, request, &discovery.DiscoveryResponse{
		VersionInfo: response.GetResponseVersion(),
		TypeUrl:     request.GetTypeUrl(),
		Nonce:       nonce,
	})
	require.NoError(t, c.completionCbs.OnStreamRequest(streamID, &discovery.DiscoveryRequest{
		Node:          request.GetNode(),
		TypeUrl:       request.GetTypeUrl(),
		VersionInfo:   response.GetResponseVersion(),
		ResponseNonce: nonce,
	}))
}

func acceptPublishedSnapshotVersions(t *testing.T, c *cacheImpl, streamID int64, node *envoy_config_core.Node, snapshot cache.ResourceSnapshot) {
	t.Helper()
	for typeURL := range typeurl.Count {
		// A version-only named RDS/EDS request does not prove that every
		// resource was delivered. Explicitly send and ACK this test baseline.
		response := publishedResponseForTest(t, c, node, typeURL)
		require.Equal(t, snapshot.GetVersion(typeURL.URL()), response.GetResponseVersion())
		acknowledgeResponse(t, c, streamID, response, "baseline")
	}
}

func mustSnapshot(t *testing.T, c *cacheImpl, nodeID string) *ciliumSnapshot {
	t.Helper()
	snapshot, err := c.getSnapshot(nodeID)
	require.NoError(t, err)
	return snapshot
}

type testNPDSListenerObserver struct {
	nodeID  string
	matches func(*envoy_config_listener.Listener) bool
	count   int
}

func (o *testNPDSListenerObserver) ApplyCommittedChanges(nodeID string, changes []ListenerChange) bool {
	if nodeID != o.nodeID {
		return false
	}
	before := o.count
	for _, change := range changes {
		if o.matches(change.Previous) {
			o.count--
		}
		if o.matches(change.Current) {
			o.count++
		}
	}
	return before > 0 && o.count == 0
}

func (o *testNPDSListenerObserver) HasNPDSListeners(nodeID string) bool {
	return nodeID != o.nodeID || o.count > 0
}

type coverageStream struct {
	cache   *cacheImpl
	id      int64
	nonce   uint64
	sub     stream.Subscription
	version string
	typeURL string
}

func (s *coverageStream) resourceType() string {
	if s.typeURL == "" {
		return typeurl.Endpoint.URL()
	}
	return s.typeURL
}

func (s *coverageStream) receive(t *testing.T, names ...string) *discovery.DiscoveryResponse {
	t.Helper()
	responses := s.watch(t, names...)
	select {
	case response := <-responses:
		return s.deliver(t, response)
	default:
		t.Fatal("expected immediate response")
		return nil
	}
}

func (s *coverageStream) deliver(t *testing.T, response cache.Response) *discovery.DiscoveryResponse {
	t.Helper()
	out, err := response.GetDiscoveryResponse()
	require.NoError(t, err)
	s.nonce++
	out.Nonce = fmt.Sprint(s.nonce)
	s.sub.SetReturnedResources(response.GetReturnedResources())
	s.cache.completionCbs.OnStreamResponse(response.GetContext(), s.id, response.GetRequest(), out)
	return out
}

func (s *coverageStream) reply(t *testing.T, response *discovery.DiscoveryResponse, rejection string, names ...string) {
	t.Helper()
	request := &discovery.DiscoveryRequest{
		TypeUrl: s.resourceType(), VersionInfo: response.GetVersionInfo(),
		ResponseNonce: response.GetNonce(), ResourceNames: names,
	}
	if rejection != "" {
		// Envoy echoes the last accepted version when rejecting a response.
		request.VersionInfo = s.version
		request.ErrorDetail = &status.Status{Message: rejection}
	}
	require.NoError(t, s.cache.completionCbs.OnStreamRequest(s.id, request))
	if rejection == "" {
		s.version = response.GetVersionInfo()
	}
	s.sub.SetResourceSubscription(names)
}

func newCoverageCache(t *testing.T) *cacheImpl {
	t.Helper()
	c := newTestCache(t, "coverage-node")
	t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil); c.completionCbs.OnStreamClosed(2, nil) })
	return c
}

// These helpers finalize caller ownership immediately while retaining the
// independent response recovery exercised by the NACK and coalescing tests.
func (c *cacheImpl) applyRevertibleResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup) error {
	rollback, err := c.ApplyResourceWithRollback(ctx, nodeID, typeURL, name, resource, wg)
	if err == nil {
		rollback.Finalize()
	}
	return err
}

func (c *cacheImpl) applyRevertibleResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set) error {
	rollback, err := c.ApplyResourcesWithRollback(ctx, nodeID, mutations, wg, waitTypeURLs)
	if err == nil {
		rollback.Finalize()
	}
	return err
}

func upsertCoverageEndpoint(t *testing.T, c *cacheImpl, name string) (*envoy_config_endpoint.ClusterLoadAssignment, <-chan error) {
	t.Helper()
	resource := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
	wg := completion.NewWaitGroup(t.Context())
	t.Cleanup(wg.Cancel)
	require.NoError(t, c.applyRevertibleResource(t.Context(), "coverage-node", typeurl.Endpoint, name, resource, wg))
	return resource, waitForCoverageCompletion(wg)
}

// Call after registering all updates in wg, as production callers do.
func waitForCoverageCompletion(wg *completion.WaitGroup) <-chan error {
	done := make(chan error, 1)
	go func() { done <- wg.Wait() }()
	return done
}

func requireCoveragePending(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("uncovered resource completed: %v", err)
	default:
	}
}

// watch leaves delivery and ACK/NACK timing to the test. receive consumes an
// immediate response through the same request/subscription setup.
func (s *coverageStream) watch(t *testing.T, names ...string) chan cache.Response {
	t.Helper()
	request := &discovery.DiscoveryRequest{
		Node: &envoy_config_core.Node{Id: "coverage-node"}, TypeUrl: s.resourceType(), ResourceNames: names, VersionInfo: s.version,
	}
	require.NoError(t, s.cache.completionCbs.OnStreamRequest(s.id, request))
	if s.nonce == 0 {
		s.sub = stream.NewSotwSubscription(names, s.resourceType() != typeurl.Secret.URL())
	} else {
		s.sub.SetResourceSubscription(names)
	}
	responses := make(chan cache.Response, 1)
	cancel, err := s.cache.CreateWatch(request, s.sub, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	return responses
}
func (state *nodeState) requireNoUnsentRollbacks(t *testing.T, msgAndArgs ...any) {
	t.Helper()
	for typeURL := range typeurl.Count {
		require.Nil(t, state.typeStates[typeURL].unsentRollback, msgAndArgs...)
	}
}

// requestSnapshotForTest drives publication through a real supported watch.
func requestSnapshotForTest(t *testing.T, c *cacheImpl, nodeID string, typeURL typeurl.Index) *ciliumSnapshot {
	t.Helper()
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeURL.URL(), ResourceNames: []string{"*"},
	}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancel)
	cancel()
	snapshot, err := c.getSnapshot(nodeID)
	require.NoError(t, err)
	return snapshot
}
