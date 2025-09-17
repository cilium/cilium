// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	status "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"

	"github.com/stretchr/testify/require"
)

// Create a mock stream
var _ v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer = (*MockStream)(nil)

type MockStream struct {
	_Send func(*v3.DeltaDiscoveryResponse) error
	_Recv func() (*v3.DeltaDiscoveryRequest, error)
	testutils.FakeGRPCServerStream
}

func (s *MockStream) Send(m *v3.DeltaDiscoveryResponse) error {
	return s._Send(m)
}

func (s *MockStream) Recv() (*v3.DeltaDiscoveryRequest, error) {
	return s._Recv()
}

// MockEndpointManager is a mock implementation of endpointmanager.EndpointManager
type MockEndpointManager struct {
	// these are the actual methods under test.
	_GetEndpoints                 func() []*endpoint.Endpoint
	_Subscribe                    func(s endpointmanager.Subscriber)
	_Unsubscribe                  func(s endpointmanager.Subscriber)
	_GetEndpointsByServiceAccount func(namespace string, serviceAccount string) []*endpoint.Endpoint
	_GetEndpointsByNamespace      func(namespace string) []*endpoint.Endpoint
}

// Ensure MockEndpointManager implements all required interfaces
var _ endpointmanager.EndpointManager = (*MockEndpointManager)(nil)
var _ endpointmanager.EndpointsLookup = (*MockEndpointManager)(nil)
var _ endpointmanager.EndpointsModify = (*MockEndpointManager)(nil)
var _ endpointmanager.EndpointResourceSynchronizer = (*MockEndpointManager)(nil)

func (m *MockEndpointManager) Lookup(id string) (*endpoint.Endpoint, error) {
	panic("MockEndpointManager.Lookup not implemented")
}

func (m *MockEndpointManager) LookupCiliumID(id uint16) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupCiliumID not implemented")
}

func (m *MockEndpointManager) LookupCNIAttachmentID(id string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupCNIAttachmentID not implemented")
}

func (m *MockEndpointManager) LookupIPv4(ipv4 string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupIPv4 not implemented")
}

func (m *MockEndpointManager) LookupIPv6(ipv6 string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupIPv6 not implemented")
}

func (m *MockEndpointManager) LookupIP(ip netip.Addr) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupIP not implemented")
}

func (m *MockEndpointManager) LookupCEPName(name string) *endpoint.Endpoint {
	panic("MockEndpointManager.LookupCEPName not implemented")
}

func (m *MockEndpointManager) GetEndpointsByPodName(name string) []*endpoint.Endpoint {
	panic("MockEndpointManager.GetEndpointsByPodName not implemented")
}

func (m *MockEndpointManager) GetEndpointsByContainerID(containerID string) []*endpoint.Endpoint {
	panic("MockEndpointManager.GetEndpointsByContainerID not implemented")
}

func (m *MockEndpointManager) GetEndpointsByServiceAccount(namespace string, serviceAccount string) []*endpoint.Endpoint {
	return m._GetEndpointsByServiceAccount(namespace, serviceAccount)
}

func (m *MockEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	return m._GetEndpoints()
}

func (m *MockEndpointManager) GetEndpointsByNamespace(namespace string) []*endpoint.Endpoint {
	return m._GetEndpointsByNamespace(namespace)
}

func (m *MockEndpointManager) GetEndpointList(params endpointapi.GetEndpointParams) []*models.Endpoint {
	panic("MockEndpointManager.GetEndpointList not implemented")
}

func (m *MockEndpointManager) EndpointExists(id uint16) bool {
	panic("MockEndpointManager.EndpointExists not implemented")
}

func (m *MockEndpointManager) GetHostEndpoint() *endpoint.Endpoint {
	panic("MockEndpointManager.GetHostEndpoint not implemented")
}

func (m *MockEndpointManager) HostEndpointExists() bool {
	panic("MockEndpointManager.HostEndpointExists not implemented")
}

func (m *MockEndpointManager) GetIngressEndpoint() *endpoint.Endpoint {
	panic("MockEndpointManager.GetIngressEndpoint not implemented")
}

func (m *MockEndpointManager) IngressEndpointExists() bool {
	panic("MockEndpointManager.IngressEndpointExists not implemented")
}

// EndpointsModify interface methods
func (m *MockEndpointManager) AddEndpoint(ep *endpoint.Endpoint) error {
	panic("MockEndpointManager.AddEndpoint not implemented")
}

func (m *MockEndpointManager) RestoreEndpoint(ep *endpoint.Endpoint) error {
	panic("MockEndpointManager.RestoreEndpoint not implemented")
}

func (m *MockEndpointManager) UpdateReferences(ep *endpoint.Endpoint) error {
	panic("MockEndpointManager.UpdateReferences not implemented")
}

func (m *MockEndpointManager) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	panic("MockEndpointManager.RemoveEndpoint not implemented")
}

// EndpointResourceSynchronizer interface methods
func (m *MockEndpointManager) RunK8sCiliumEndpointSync(ep *endpoint.Endpoint, hr cell.Health) {
	panic("MockEndpointManager.RunK8sCiliumEndpointSync not implemented")
}

func (m *MockEndpointManager) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
	panic("MockEndpointManager.DeleteK8sCiliumEndpointSync not implemented")
}

// EndpointManager interface methods
func (m *MockEndpointManager) Subscribe(s endpointmanager.Subscriber) {
	m._Subscribe(s)
}

func (m *MockEndpointManager) Unsubscribe(s endpointmanager.Subscriber) {
	m._Unsubscribe(s)
}

func (m *MockEndpointManager) UpdatePolicyMaps(ctx context.Context, notifyWg *sync.WaitGroup) *sync.WaitGroup {
	panic("MockEndpointManager.UpdatePolicyMaps not implemented")
}

func (m *MockEndpointManager) RegenerateAllEndpoints(regenMetadata *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	panic("MockEndpointManager.RegenerateAllEndpoints not implemented")
}

func (m *MockEndpointManager) TriggerRegenerateAllEndpoints() {
	panic("MockEndpointManager.TriggerRegenerateAllEndpoints not implemented")
}

func (m *MockEndpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	panic("MockEndpointManager.WaitForEndpointsAtPolicyRev not implemented")
}

func (m *MockEndpointManager) OverrideEndpointOpts(om option.OptionMap) {
	panic("MockEndpointManager.OverrideEndpointOpts not implemented")
}

func (m *MockEndpointManager) InitHostEndpointLabels(ctx context.Context) {
	panic("MockEndpointManager.InitHostEndpointLabels not implemented")
}

func (m *MockEndpointManager) UpdatePolicy(idsToRegen *set.Set[identity.NumericIdentity], fromRev, toRev uint64) {
	panic("MockEndpointManager.UpdatePolicy not implemented")
}

func TestStreamProcessorStart(t *testing.T) {
	t.Run("No start on stream ctx canceled", func(t *testing.T) {
		// Create a canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately to simulate an already dead context

		// Create a mock stream that returns the canceled context
		mockStream := &MockStream{}
		mockStream.OnContext = func() context.Context {
			return ctx
		}

		// Create mock endpoint manager
		var unsub bool
		mockEM := &MockEndpointManager{
			_Unsubscribe: func(s endpointmanager.Subscriber) {
				unsub = true
			},
		}

		// Create channels for the stream processor
		streamRecv := make(chan *v3.DeltaDiscoveryRequest, 1)
		endpointEventRecv := make(chan *EndpointEvent, 1)

		// Create stream processor
		sp := NewStreamProcessor(&StreamProcessorParams{
			Stream:            mockStream,
			StreamRecv:        streamRecv,
			EndpointEventRecv: endpointEventRecv,
			EndpointManager:   mockEM,
			Log:               slog.New(slog.DiscardHandler),
		})

		timeOutCTX, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()

		// Start should return immediately since context is already canceled
		// We use a done channel to detect when Start() returns
		done := make(chan struct{})
		go func() {
			sp.Start()
			close(done)
		}()

		// Wait for Start() to return - it should return quickly since context is canceled
		select {
		case <-done:
			// Success - Start() returned as expected
			if !unsub {
				t.Fatal("Expected Unsubscribe to be called on context cancel")
			}
		case <-timeOutCTX.Done():
			t.Fatal("Start() did not return within timeout when context was canceled")
		}
	})
}

func TestStreamProcessorEndpointEvents(t *testing.T) {
	t.Run("Multi Event", func(t *testing.T) {
		// Test UIDs for the three events
		testUIDs := []string{
			"create-uid-1-12345678-1234-1234-1234-123456789abc",
			"remove-uid-2-87654321-4321-4321-4321-cba987654321",
			"create-uid-3-abcdef12-5678-9012-3456-789012345678",
		}

		// Create test endpoints for our three events
		createEp1 := &endpoint.Endpoint{
			ID:           2001,
			K8sUID:       testUIDs[0],
			K8sPodName:   "create-pod-1",
			K8sNamespace: "default",
			IPv4:         netip.MustParseAddr("10.1.1.100"),
		}
		createPod1 := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "test-node-1",
				ServiceAccountName: "test-sa-1",
			},
		}
		createEp1.SetPod(createPod1)

		removeEp := &endpoint.Endpoint{
			ID:           2002,
			K8sUID:       testUIDs[1],
			K8sPodName:   "remove-pod-2",
			K8sNamespace: "kube-system",
			IPv4:         netip.MustParseAddr("10.2.2.200"),
		}
		removePod := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "test-node-2",
				ServiceAccountName: "test-sa-2",
			},
		}
		removeEp.SetPod(removePod)

		createEp2 := &endpoint.Endpoint{
			ID:           2003,
			K8sUID:       testUIDs[2],
			K8sPodName:   "create-pod-3",
			K8sNamespace: "cilium-system",
			IPv6:         netip.MustParseAddr("fd00::3:300"),
		}
		createPod3 := &slim_corev1.Pod{
			Spec: slim_corev1.PodSpec{
				NodeName:           "test-node-3",
				ServiceAccountName: "test-sa-3",
			},
		}
		createEp2.SetPod(createPod3)

		// Create the three events in sequence: CREATE, REMOVE, CREATE
		event1 := &EndpointEvent{Type: CREATE, Endpoint: createEp1}
		event2 := &EndpointEvent{Type: REMOVED, Endpoint: removeEp}
		event3 := &EndpointEvent{Type: CREATE, Endpoint: createEp2}

		// Setup mock stream to capture the response
		var capturedResponse *v3.DeltaDiscoveryResponse
		mockStream := &MockStream{}
		mockStream.OnSendMsg = func(m any) error {
			capturedResponse = m.(*v3.DeltaDiscoveryResponse)
			return nil
		}

		// Create endpoint event channel and populate with events
		endpointEventChan := make(chan *EndpointEvent, 3)
		endpointEventChan <- event1
		endpointEventChan <- event2
		endpointEventChan <- event3

		// Create StreamProcessor with the populated channel
		sp := &StreamProcessor{
			stream:        mockStream,
			endpointRecv:  endpointEventChan,
			expectedNonce: make(map[string]struct{}),
		}

		// Call handleEPEvent directly to test channel draining
		// We need to retrieve the first event from the channel manually since
		// handleEPEvent expects to receive one event as parameter and then drain the rest
		firstEvent := <-endpointEventChan
		err := sp.handleEPEvent(firstEvent)
		require.NoError(t, err, "handleEPEvent should not error")

		// Verify response was sent
		require.NotNil(t, capturedResponse, "Response should have been captured")

		// Verify response structure
		require.Equal(t, xdsTypeURLAddress, capturedResponse.TypeUrl)
		require.NotEmpty(t, capturedResponse.Nonce, "Nonce should be generated")

		// Verify all three events were processed:
		// - 2 CREATE events should result in 2 resources
		// - 1 REMOVE event should result in 1 removed resource
		require.Len(t, capturedResponse.Resources, 2, "Should have 2 CREATE resources")
		require.Len(t, capturedResponse.RemovedResources, 1, "Should have 1 REMOVE resource")

		// Verify UIDs match expected CREATE and REMOVE events
		// NOTE: proper validation of response is done in endpoint_event_test.go
		expectedCreateUIDs := []string{testUIDs[0], testUIDs[2]} // event1 and event3
		expectedRemoveUIDs := []string{testUIDs[1]}              // event2

		actualCreateUIDs := make([]string, len(capturedResponse.Resources))
		for i, resource := range capturedResponse.Resources {
			actualCreateUIDs[i] = resource.Name
		}
		require.ElementsMatch(t, expectedCreateUIDs, actualCreateUIDs, "CREATE resource UIDs should match expected")
		require.ElementsMatch(t, expectedRemoveUIDs, capturedResponse.RemovedResources, "REMOVE resource UIDs should match expected")

		// Verify nonce was added to expectedNonce map
		require.Contains(t, sp.expectedNonce, capturedResponse.Nonce, "Nonce should be tracked as expected")

		// Verify channel was fully drained
		select {
		case e := <-endpointEventChan:
			// log remaining endpoint
			t.Logf("Remaining endpoint event in channel: %+v", e)
			t.Fatal("Channel should be fully drained")
		default:
			// Channel is empty as expected
		}
	})
}

// TestStreamProcessorDeltaDiscoveryRequest ensures correctness when handling a
// DeltaDiscoveryRequest from the client.
func TestStreamProcessorDeltaDiscoveryRequest(t *testing.T) {
	t.Run("Ack", func(t *testing.T) {
		sp := &StreamProcessor{
			expectedNonce: map[string]struct{}{
				"x": {},
			},
			log: slog.New(slog.DiscardHandler),
		}

		req := &v3.DeltaDiscoveryRequest{
			TypeUrl:       "xdsTypeURLAddress",
			ResponseNonce: "x",
		}

		if err := sp.handleDeltaDiscoveryReq(req); err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		// ensure expected nonce is removed
		if _, ok := sp.expectedNonce[req.ResponseNonce]; ok {
			t.Fatalf("Expected nonce %q to be removed, but it still exists", req.ResponseNonce)
		}
	})

	t.Run("Unexpected Nonce", func(t *testing.T) {
		sp := &StreamProcessor{
			// no Nonce recorded
			expectedNonce: map[string]struct{}{},
			log:           slog.New(slog.DiscardHandler),
		}

		req := &v3.DeltaDiscoveryRequest{
			TypeUrl: "xdsTypeURLAddress",
			// but response nonce sent, we should error here.
			ResponseNonce: "x",
			ErrorDetail: &status.Status{
				Code:    1,
				Message: "test error",
			},
		}

		if err := sp.handleDeltaDiscoveryReq(req); err == nil {
			t.Fatal("Expected error for unexpected nonce, but got none")
		} else {
			t.Logf("Received expected error: %v", err)
		}
	})

	t.Run("Address Stream Initialization", func(t *testing.T) {
		var recordedResponse *v3.DeltaDiscoveryResponse
		mockStream := &MockStream{}
		mockStream.OnSendMsg = func(m any) error {
			recordedResponse = m.(*v3.DeltaDiscoveryResponse)
			return nil
		}

		var sub bool
		expectedUIDs := []string{
			"12345678-1234-1234-1234-123456789abc", // ep1
			"87654321-4321-4321-4321-cba987654321", // ep2
			"abcdef12-5678-9012-3456-789012345678", // ep3
		}
		mockEndpointManager := &MockEndpointManager{
			_Subscribe: func(s endpointmanager.Subscriber) {
				sub = true
			},
			_GetEndpoints: func() []*endpoint.Endpoint {
				// Create multiple test endpoints to ensure comprehensive transformation testing
				endpoints := make([]*endpoint.Endpoint, 0, 3)

				// Endpoint 1: Full IPv4 + IPv6 endpoint with complete K8s metadata
				ep1 := &endpoint.Endpoint{
					ID:           1001,
					K8sUID:       expectedUIDs[0],
					K8sPodName:   "test-pod-1",
					K8sNamespace: "default",
					IPv4:         netip.MustParseAddr("10.0.1.100"),
					IPv6:         netip.MustParseAddr("fd00::1:100"),
				}
				// Create and set a mock Pod for ep1
				pod1 := &slim_corev1.Pod{
					Spec: slim_corev1.PodSpec{
						NodeName:           "node-1",
						ServiceAccountName: "default-sa",
					},
				}
				ep1.SetPod(pod1)
				endpoints = append(endpoints, ep1)

				// Endpoint 2: IPv4-only endpoint with different metadata
				ep2 := &endpoint.Endpoint{
					ID:           1002,
					K8sUID:       expectedUIDs[1],
					K8sPodName:   "test-pod-2",
					K8sNamespace: "kube-system",
					IPv4:         netip.MustParseAddr("10.0.2.200"),
				}
				// Create and set a mock Pod for ep2
				pod2 := &slim_corev1.Pod{
					Spec: slim_corev1.PodSpec{
						NodeName:           "node-2",
						ServiceAccountName: "kube-system-sa",
					},
				}
				ep2.SetPod(pod2)
				endpoints = append(endpoints, ep2)

				// Endpoint 3: IPv6-only endpoint with different namespace
				ep3 := &endpoint.Endpoint{
					ID:           1003,
					K8sUID:       expectedUIDs[2],
					K8sPodName:   "test-pod-3",
					K8sNamespace: "cilium-system",
					IPv6:         netip.MustParseAddr("fd00::2:300"),
				}
				// Create and set a mock Pod for ep3
				pod3 := &slim_corev1.Pod{
					Spec: slim_corev1.PodSpec{
						NodeName:           "node-3",
						ServiceAccountName: "cilium-sa",
					},
				}
				ep3.SetPod(pod3)
				endpoints = append(endpoints, ep3)

				return endpoints
			},
		}

		sp := StreamProcessor{
			stream:          mockStream,
			endpointManager: mockEndpointManager,
			expectedNonce:   make(map[string]struct{}),
			log:             slog.New(slog.DiscardHandler),
		}

		req := &v3.DeltaDiscoveryRequest{
			TypeUrl:                  xdsTypeURLAddress,
			ResourceNamesSubscribe:   []string{},
			ResourceNamesUnsubscribe: []string{},
		}

		if err := sp.handleDeltaDiscoveryReq(req); err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		// validate response
		require.NotNil(t, recordedResponse, "No response was recorded")

		// Validate response structure
		require.Equal(t, xdsTypeURLAddress, recordedResponse.TypeUrl, "Incorrect TypeUrl")
		require.NotEmpty(t, recordedResponse.Nonce, "Nonce should not be empty")
		require.Empty(t, recordedResponse.RemovedResources, "No resources should be removed")
		require.Len(t, recordedResponse.Resources, 3, "Should have 3 resources for our 3 endpoints")

		// Validate StreamProcessor adds sent Nonce to expected Nonces
		if _, ok := sp.expectedNonce[recordedResponse.Nonce]; !ok {
			t.Fatal("Expected nonce to be tracked as expected")
		}

		// Validate UIDs match between mock endpoints and response resources
		// NOTE: proper validation of response is done in endpoint_event_test.go
		actualUIDs := make([]string, len(recordedResponse.Resources))
		for i, resource := range recordedResponse.Resources {
			actualUIDs[i] = resource.Name
		}
		require.ElementsMatch(t, expectedUIDs, actualUIDs, "All expected endpoint UIDs should be present in response")

		// Validate subscription occurred
		require.True(t, sub, "EndpointManager.Subscribe should have been called")

	})
}
