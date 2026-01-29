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

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	status "google.golang.org/genproto/googleapis/rpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachineryTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

// makeCEP is a test helper that creates a CiliumEndpoint with the given parameters.
// Pass empty strings for optional parameters to use defaults.
func makeCEP(name, namespace, ip string) *types.CiliumEndpoint {
	if namespace == "" {
		namespace = "default"
	}

	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       apimachineryTypes.UID(name + "-uid"),
		},
	}

	if ip != "" {
		cep.Networking = &v2.EndpointNetworking{
			Addressing: v2.AddressPairList{
				{IPV4: ip},
			},
		}
	}

	return cep
}

// enrollNamespace is a test helper that inserts a namespace into the enrolled namespaces table
func enrollNamespace(t *testing.T, db *statedb.DB, tbl statedb.RWTable[*table.EnrolledNamespace], namespace string) {
	txn := db.WriteTxn(tbl)
	_, _, err := tbl.Insert(txn, &table.EnrolledNamespace{
		Name:   namespace,
		Status: reconciler.StatusDone(),
	})
	require.NoError(t, err, "Failed to enroll namespace %s", namespace)
	txn.Commit()
}

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

type MockEndpointEventSource struct {
	subscribeCalled bool
	db              *statedb.DB
	enrolledNsTable statedb.RWTable[*table.EnrolledNamespace]
}

// SubscribeToEndpointEvents is a no-op for the mock since we
// can rely on sending events to EndpointEventRecv directly in tests.
func (m *MockEndpointEventSource) SubscribeToEndpointEvents(ctx context.Context, wg *sync.WaitGroup) {
	m.subscribeCalled = true
	wg.Done()
}

// ListAllEndpoints returns endpoints from enrolled namespaces only (mimicking real behavior).
func (m *MockEndpointEventSource) ListAllEndpoints(ctx context.Context) ([]*types.CiliumEndpoint, error) {
	// Create multiple test endpoints to ensure comprehensive transformation testing
	ceps := make([]*types.CiliumEndpoint, 0, 3)
	expectedUIDs := []string{
		"12345678-1234-1234-1234-123456789abc", // ep1
		"87654321-4321-4321-4321-cba987654321", // ep2
		"abcdef12-5678-9012-3456-789012345678", // ep3
	}

	// Endpoint 1: Full IPv4 + IPv6 endpoint with complete K8s metadata (enrolled namespace)
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

	// Endpoint 2: IPv4-only endpoint with different metadata (unenrolled namespace)
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

	// Endpoint 3: IPv6-only endpoint with different namespace (enrolled namespace)
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

	// Only include endpoints from enrolled namespaces
	if m.db != nil && m.enrolledNsTable != nil {
		txn := m.db.ReadTxn()

		// Check if "default" is enrolled
		if _, _, found := m.enrolledNsTable.Get(txn, table.EnrolledNamespacesNameIndex.Query("default")); found {
			ceps = append(ceps, endpointToCiliumEndpoint(ep1))
		}

		// Check if "kube-system" is enrolled
		if _, _, found := m.enrolledNsTable.Get(txn, table.EnrolledNamespacesNameIndex.Query("kube-system")); found {
			ceps = append(ceps, endpointToCiliumEndpoint(ep2))
		}

		// Check if "cilium-system" is enrolled
		if _, _, found := m.enrolledNsTable.Get(txn, table.EnrolledNamespacesNameIndex.Query("cilium-system")); found {
			ceps = append(ceps, endpointToCiliumEndpoint(ep3))
		}
	} else {
		// If no enrollment table provided, return all (for backwards compatibility)
		ceps = append(ceps, endpointToCiliumEndpoint(ep1))
		ceps = append(ceps, endpointToCiliumEndpoint(ep2))
		ceps = append(ceps, endpointToCiliumEndpoint(ep3))
	}

	return ceps, nil
}

func (m *MockEndpointEventSource) GetSubscriptionStatus() bool {
	return m.subscribeCalled
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

		// Create channels for the stream processor
		streamRecv := make(chan *v3.DeltaDiscoveryRequest, 1)
		endpointEventRecv := make(chan *EndpointEvent, 1)

		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err, "Failed to create EnrolledNamespaces table")

		// Create stream processor
		sp := NewStreamProcessor(&StreamProcessorParams{
			Stream:                 mockStream,
			StreamRecv:             streamRecv,
			EndpointEventRecv:      endpointEventRecv,
			DB:                     db,
			EnrolledNamespaceTable: tbl,
			Log:                    slog.New(slog.DiscardHandler),
		})
		sp.endpointSource = &MockEndpointEventSource{}

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
		case <-timeOutCTX.Done():
			t.Fatal("Start() did not return in time despite canceled context")
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
		event1 := &EndpointEvent{Type: CREATE, CiliumEndpoint: endpointToCiliumEndpoint(createEp1)}
		event2 := &EndpointEvent{Type: REMOVED, CiliumEndpoint: endpointToCiliumEndpoint(removeEp)}
		event3 := &EndpointEvent{Type: CREATE, CiliumEndpoint: endpointToCiliumEndpoint(createEp2)}

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
			t.Fatalf("Channel should be empty, but found event: %+v", e)
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
		sp.endpointSource = &MockEndpointEventSource{}

		req := &v3.DeltaDiscoveryRequest{
			TypeUrl:       "xdsTypeURLAddress",
			ResponseNonce: "x",
		}
		err := sp.handleDeltaDiscoveryReq(req)
		require.NoError(t, err)

		// ensure expected nonce is removed
		_, ok := sp.expectedNonce["x"]
		require.False(t, ok)
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
		err := sp.handleDeltaDiscoveryReq(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected nonce")
	})

	t.Run("Address Stream Initialization with enrolled namespaces", func(t *testing.T) {
		var recordedResponse *v3.DeltaDiscoveryResponse
		mockStream := &MockStream{}
		mockStream.OnContext = func() context.Context {
			return context.Background()
		}
		mockStream.OnSendMsg = func(m any) error {
			recordedResponse = m.(*v3.DeltaDiscoveryResponse)
			return nil
		}

		// These UIDs must match what MockEndpointEventSource.ListAllEndpoints returns
		expectedUIDs := []string{
			"12345678-1234-1234-1234-123456789abc", // ep1 - default (enrolled)
			// ep2 - kube-system (NOT enrolled) - should be filtered out
			"abcdef12-5678-9012-3456-789012345678", // ep3 - cilium-system (enrolled)
		}

		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		// Enroll only "default" and "cilium-system"
		enrollNamespace(t, db, tbl, "default")
		enrollNamespace(t, db, tbl, "cilium-system")

		sp := StreamProcessor{
			stream:                 mockStream,
			expectedNonce:          make(map[string]struct{}),
			log:                    slog.New(slog.DiscardHandler),
			db:                     db,
			enrolledNamespaceTable: tbl,
		}
		sp.endpointSource = &MockEndpointEventSource{
			subscribeCalled: false,
			db:              db,
			enrolledNsTable: tbl,
		}

		req := &v3.DeltaDiscoveryRequest{
			TypeUrl: xdsTypeURLAddress,
		}

		err = sp.handleAddressTypeURL(req)
		require.NoError(t, err)

		// validate response
		require.NotNil(t, recordedResponse)

		// Validate response structure - should only have 2 endpoints (default and cilium-system)
		require.Equal(t, xdsTypeURLAddress, recordedResponse.TypeUrl)
		require.Len(t, recordedResponse.Resources, 2, "Should only include endpoints from enrolled namespaces")
		require.Empty(t, recordedResponse.RemovedResources)

		// Validate StreamProcessor adds sent Nonce to expected Nonces
		require.NotEmpty(t, recordedResponse.Nonce)
		_, ok := sp.expectedNonce[recordedResponse.Nonce]
		require.True(t, ok)

		// Validate UIDs match between mock endpoints and response resources (excluding kube-system)
		// NOTE: proper validation of response is done in endpoint_event_test.go
		actualUIDs := make([]string, len(recordedResponse.Resources))
		for i, resource := range recordedResponse.Resources {
			actualUIDs[i] = resource.Name
		}
		require.ElementsMatch(t, expectedUIDs, actualUIDs, "Only enrolled namespace endpoints should be included")

		// Validate subscription occurred
		mockSource := sp.endpointSource.(*MockEndpointEventSource)
		require.True(t, mockSource.GetSubscriptionStatus())
	})
}

func TestComputeEndpointDiff(t *testing.T) {
	t.Run("detect new endpoints", func(t *testing.T) {
		oldCEPs := map[string]*types.CiliumEndpoint{}
		newCEPs := map[string]*types.CiliumEndpoint{
			"default/pod-1": makeCEP("pod-1", "", ""),
			"default/pod-2": makeCEP("pod-2", "", ""),
		}

		added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)
		require.Len(t, added, 2)
		require.Empty(t, updated)
		require.Empty(t, removed)
	})

	t.Run("detect removed endpoints", func(t *testing.T) {
		oldCEPs := map[string]*types.CiliumEndpoint{
			"default/pod-1": makeCEP("pod-1", "", ""),
			"default/pod-2": makeCEP("pod-2", "", ""),
		}
		newCEPs := map[string]*types.CiliumEndpoint{}

		added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)
		require.Empty(t, added)
		require.Empty(t, updated)
		require.Len(t, removed, 2)
	})

	t.Run("detect updated endpoints", func(t *testing.T) {
		oldCEPs := map[string]*types.CiliumEndpoint{
			"default/pod-1": makeCEP("pod-1", "", "10.0.0.1"),
		}
		newCEPs := map[string]*types.CiliumEndpoint{
			"default/pod-1": makeCEP("pod-1", "", "10.0.0.2"),
		}

		added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)
		require.Empty(t, added)
		require.Len(t, updated, 1)
		require.Empty(t, removed)
	})

	t.Run("detect mixed changes", func(t *testing.T) {
		oldCEPs := map[string]*types.CiliumEndpoint{
			"default/pod-1": makeCEP("pod-1", "", "10.0.0.1"),
			"default/pod-2": makeCEP("pod-2", "", "10.0.0.2"),
		}
		newCEPs := map[string]*types.CiliumEndpoint{
			"default/pod-1": makeCEP("pod-1", "", "10.0.0.99"), // updated
			"default/pod-3": makeCEP("pod-3", "", "10.0.0.3"),  // added
		}

		added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)
		require.Len(t, added, 1)
		require.Len(t, updated, 1)
		require.Len(t, removed, 1)
	})
}

func TestEmitEndpointEvents(t *testing.T) {
	eventChan := make(chan *EndpointEvent, 10)
	sp := &StreamProcessor{
		endpointRecv: eventChan,
	}
	es := &EndpointSource{sp: sp}

	endpoints := []*types.CiliumEndpoint{
		makeCEP("pod-1", "", ""),
		makeCEP("pod-2", "", ""),
	}

	es.emitEndpointEvents(CREATE, endpoints)

	require.Len(t, eventChan, 2)
	event1 := <-eventChan
	event2 := <-eventChan

	require.Equal(t, CREATE, event1.Type)
	require.Equal(t, CREATE, event2.Type)
	require.Equal(t, "pod-1", event1.CiliumEndpoint.Name)
	require.Equal(t, "pod-2", event2.CiliumEndpoint.Name)
}

func TestHandleCESUpsert(t *testing.T) {
	tests := []struct {
		name              string
		initialCES        *v2alpha1.CiliumEndpointSlice // To populate the cache
		newCES            *v2alpha1.CiliumEndpointSlice
		key               resource.Key
		enrolledNamespace bool // whether to enroll the namespace
		expectedAdded     int
		expectedUpdated   int
		expectedRemoved   int
	}{
		{
			name:       "new CES with endpoints in enrolled namespace",
			initialCES: nil, // Empty cache
			newCES: &v2alpha1.CiliumEndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ces-1",
					Namespace: "default",
				},
				Endpoints: []v2alpha1.CoreCiliumEndpoint{
					{
						Name:       "pod-1",
						IdentityID: 100,
					},
					{
						Name:       "pod-2",
						IdentityID: 200,
					},
				},
			},
			key:               resource.Key{Name: "ces-1", Namespace: "default"},
			enrolledNamespace: true,
			expectedAdded:     2,
			expectedUpdated:   0,
			expectedRemoved:   0,
		},
		{
			name:       "new CES with endpoints in unenrolled namespace",
			initialCES: nil,
			newCES: &v2alpha1.CiliumEndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ces-1",
					Namespace: "unenrolled",
				},
				Endpoints: []v2alpha1.CoreCiliumEndpoint{
					{
						Name:       "pod-1",
						IdentityID: 100,
					},
				},
			},
			key:               resource.Key{Name: "ces-1", Namespace: "unenrolled"},
			enrolledNamespace: false,
			expectedAdded:     0, // Should be skipped
			expectedUpdated:   0,
			expectedRemoved:   0,
		},
		{
			name: "update existing CES - add and remove endpoints in enrolled namespace",
			initialCES: &v2alpha1.CiliumEndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ces-1",
					Namespace: "default",
				},
				Endpoints: []v2alpha1.CoreCiliumEndpoint{
					{
						Name:       "pod-1",
						IdentityID: 100,
					},
					{
						Name:       "pod-2",
						IdentityID: 200,
					},
				},
			},
			newCES: &v2alpha1.CiliumEndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ces-1",
					Namespace: "default",
				},
				Endpoints: []v2alpha1.CoreCiliumEndpoint{
					{
						Name:       "pod-2",
						IdentityID: 200,
					},
					{
						Name:       "pod-3",
						IdentityID: 300,
					},
				},
			},
			key:               resource.Key{Name: "ces-1", Namespace: "default"},
			enrolledNamespace: true,
			expectedAdded:     1, // pod-3
			expectedUpdated:   0, // pod-2 unchanged
			expectedRemoved:   1, // pod-1
		},
		{
			name: "update existing CES - modify endpoint in enrolled namespace",
			initialCES: &v2alpha1.CiliumEndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ces-1",
					Namespace: "default",
				},
				Endpoints: []v2alpha1.CoreCiliumEndpoint{
					{
						Name:       "pod-1",
						IdentityID: 100,
					},
				},
			},
			newCES: &v2alpha1.CiliumEndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ces-1",
					Namespace: "default",
				},
				Endpoints: []v2alpha1.CoreCiliumEndpoint{
					{
						Name:       "pod-1",
						IdentityID: 999, // Changed identity
					},
				},
			},
			key:               resource.Key{Name: "ces-1", Namespace: "default"},
			enrolledNamespace: true,
			expectedAdded:     1, // pod-1 with new identity is emitted as CREATE
			expectedUpdated:   0,
			expectedRemoved:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cesCache := make(map[resource.Key]map[string]*types.CiliumEndpoint)

			// Setup database and enrolled namespace table
			db := statedb.New()
			tbl, err := table.NewEnrolledNamespacesTable(db)
			require.NoError(t, err)

			// Enroll namespace if required
			if tt.enrolledNamespace {
				enrollNamespace(t, db, tbl, tt.newCES.GetObjectMeta().GetNamespace())
			}

			// Populate cache if initial CES provided
			if tt.initialCES != nil {
				cesCache[tt.key] = convertCESToEndpointMap(tt.initialCES)
			}

			eventChan := make(chan *EndpointEvent, 10)
			sp := &StreamProcessor{
				endpointRecv:           eventChan,
				db:                     db,
				enrolledNamespaceTable: tbl,
				log:                    slog.New(slog.DiscardHandler),
			}
			es := &EndpointSource{sp: sp}

			es.handleCESUpsert(tt.newCES, cesCache, tt.key)

			// Count event types
			addedCount := 0
			removedCount := 0
			close(eventChan)
			for event := range eventChan {
				switch event.Type {
				case CREATE:
					addedCount++
				case REMOVED:
					removedCount++
				}
			}

			require.Equal(t, tt.expectedAdded, addedCount, "Added count mismatch")
			require.Equal(t, tt.expectedRemoved, removedCount, "Removed count mismatch")
		})
	}
}

func TestHandleCESDelete(t *testing.T) {
	t.Run("delete CES in enrolled namespace", func(t *testing.T) {
		cesCache := map[resource.Key]map[string]*types.CiliumEndpoint{
			{Name: "ces-1", Namespace: "default"}: {
				"default/pod-1": makeCEP("pod-1", "", ""),
				"default/pod-2": makeCEP("pod-2", "", ""),
			},
		}

		ces := &v2alpha1.CiliumEndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ces-1",
				Namespace: "default",
			},
			Endpoints: []v2alpha1.CoreCiliumEndpoint{
				{
					Name:       "pod-1",
					IdentityID: 100,
				},
				{
					Name:       "pod-2",
					IdentityID: 200,
				},
			},
		}
		key := resource.Key{Name: "ces-1", Namespace: "default"}

		// Setup database and enroll namespace
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)
		enrollNamespace(t, db, tbl, "default")

		eventChan := make(chan *EndpointEvent, 10)
		sp := &StreamProcessor{
			endpointRecv:           eventChan,
			db:                     db,
			enrolledNamespaceTable: tbl,
			log:                    slog.New(slog.DiscardHandler),
		}
		es := &EndpointSource{sp: sp}

		es.handleCESDelete(ces, cesCache, key)

		// Should emit REMOVED events for all endpoints
		require.Len(t, eventChan, 2)

		removedCount := 0
		close(eventChan)
		for event := range eventChan {
			require.Equal(t, REMOVED, event.Type)
			removedCount++
		}
		require.Equal(t, 2, removedCount)

		// Verify cache entry was deleted
		_, exists := cesCache[key]
		require.False(t, exists, "cache entry should be deleted")
	})

	t.Run("delete CES in unenrolled namespace", func(t *testing.T) {
		cesCache := map[resource.Key]map[string]*types.CiliumEndpoint{
			{Name: "ces-1", Namespace: "unenrolled"}: {
				"unenrolled/pod-1": makeCEP("pod-1", "unenrolled", ""),
			},
		}

		ces := &v2alpha1.CiliumEndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ces-1",
				Namespace: "unenrolled",
			},
			Endpoints: []v2alpha1.CoreCiliumEndpoint{
				{
					Name:       "pod-1",
					IdentityID: 100,
				},
			},
		}
		key := resource.Key{Name: "ces-1", Namespace: "unenrolled"}

		// Setup database but DON'T enroll namespace
		db := statedb.New()
		tbl, err := table.NewEnrolledNamespacesTable(db)
		require.NoError(t, err)

		eventChan := make(chan *EndpointEvent, 10)
		sp := &StreamProcessor{
			endpointRecv:           eventChan,
			db:                     db,
			enrolledNamespaceTable: tbl,
			log:                    slog.New(slog.DiscardHandler),
		}
		es := &EndpointSource{sp: sp}

		es.handleCESDelete(ces, cesCache, key)

		// Should NOT emit any events since namespace is not enrolled
		require.Empty(t, eventChan, "No events should be emitted for unenrolled namespace")

		// Cache should NOT be modified for unenrolled namespaces
		_, exists := cesCache[key]
		require.True(t, exists, "cache entry should remain for unenrolled namespace")
	})
}
