// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/table"
	"github.com/cilium/cilium/pkg/ztunnel/xds"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MockEndpointManager is a mock implementation of endpointmanager.EndpointManager.
// It provides minimal functionality needed for testing the enrollment reconciler.
type MockEndpointManager struct {
	endpoints   []*endpoint.Endpoint
	subscribers map[endpointmanager.Subscriber]struct{}
}

// Ensure MockEndpointManager implements all required interfaces.
var _ endpointmanager.EndpointManager = (*MockEndpointManager)(nil)
var _ endpointmanager.EndpointsLookup = (*MockEndpointManager)(nil)
var _ endpointmanager.EndpointsModify = (*MockEndpointManager)(nil)
var _ endpointmanager.EndpointResourceSynchronizer = (*MockEndpointManager)(nil)

// EndpointsLookup interface methods

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
	panic("MockEndpointManager.GetEndpointsByServiceAccount not implemented")
}

// GetEndpoints returns all endpoints managed by this mock.
func (m *MockEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	return m.endpoints
}

// GetEndpointsByNamespace returns endpoints in the specified namespace.
func (m *MockEndpointManager) GetEndpointsByNamespace(namespace string) []*endpoint.Endpoint {
	var eps []*endpoint.Endpoint
	for _, ep := range m.endpoints {
		if ep.K8sNamespace == namespace {
			eps = append(eps, ep)
		}
	}
	return eps
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

// Subscribe adds a subscriber to the endpoint manager.
func (m *MockEndpointManager) Subscribe(s endpointmanager.Subscriber) {
	if m.subscribers == nil {
		m.subscribers = make(map[endpointmanager.Subscriber]struct{})
	}
	m.subscribers[s] = struct{}{}
}

// Unsubscribe removes a subscriber from the endpoint manager.
func (m *MockEndpointManager) Unsubscribe(s endpointmanager.Subscriber) {
	delete(m.subscribers, s)
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

// MockEndpointEnroller is a mock implementation of zds.EndpointEnroller.
// It tracks enrollment operations for testing purposes.
type MockEndpointEnroller struct {
	enrolledEndpoints map[uint16]*endpoint.Endpoint
	disenrolledIDs    []uint16
	enrollErr         error
	disenrollErr      error
}

// NewMockEndpointEnroller creates a new mock endpoint enroller.
func NewMockEndpointEnroller() *MockEndpointEnroller {
	return &MockEndpointEnroller{
		enrolledEndpoints: make(map[uint16]*endpoint.Endpoint),
		disenrolledIDs:    []uint16{},
	}
}

// EnrollEndpoint enrolls an endpoint to ztunnel.
func (m *MockEndpointEnroller) EnrollEndpoint(ep *endpoint.Endpoint) error {
	if m.enrollErr != nil {
		return m.enrollErr
	}
	m.enrolledEndpoints[ep.ID] = ep
	return nil
}

// DisenrollEndpoint disenrolls an endpoint from ztunnel.
func (m *MockEndpointEnroller) DisenrollEndpoint(ep *endpoint.Endpoint) error {
	if m.disenrollErr != nil {
		return m.disenrollErr
	}
	delete(m.enrolledEndpoints, ep.ID)
	m.disenrolledIDs = append(m.disenrolledIDs, ep.ID)
	return nil
}

// SeedInitialSnapshot sends an initial snapshot of endpoints to ztunnel.
func (m *MockEndpointEnroller) SeedInitialSnapshot(endpoints ...*endpoint.Endpoint) {
	for _, ep := range endpoints {
		m.enrolledEndpoints[ep.ID] = ep
	}
}

// MockRestorer is a mock implementation of endpointstate.Restorer.
type MockRestorer struct {
	waitErr error
}

func (m *MockRestorer) WaitForEndpointRestore(ctx context.Context) error {
	return m.waitErr
}

func (m *MockRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return m.waitErr
}

func (m *MockRestorer) WaitForInitialPolicy(ctx context.Context) error {
	return m.waitErr
}

var _ endpointstate.Restorer = &MockRestorer{}

// MockCiliumEndpointResource is a mock implementation of resource.Resource[*types.CiliumEndpoint].
type MockCiliumEndpointResource struct {
	store    *MockCiliumEndpointStore
	storeErr error
}

func (m *MockCiliumEndpointResource) Store(ctx context.Context) (resource.Store[*types.CiliumEndpoint], error) {
	if m.storeErr != nil {
		return nil, m.storeErr
	}
	return m.store, nil
}

func (m *MockCiliumEndpointResource) Observe(ctx context.Context, next func(resource.Event[*types.CiliumEndpoint]), complete func(error)) {
	panic("MockCiliumEndpointResource.Observe not implemented")
}

func (m *MockCiliumEndpointResource) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*types.CiliumEndpoint] {
	panic("MockCiliumEndpointResource.Events not implemented")
}

// MockCiliumEndpointStore is a mock implementation of resource.Store[*types.CiliumEndpoint].
type MockCiliumEndpointStore struct {
	endpoints map[string]*types.CiliumEndpoint
}

func (m *MockCiliumEndpointStore) List() []*types.CiliumEndpoint {
	panic("MockCiliumEndpointStore.List not implemented")
}

func (m *MockCiliumEndpointStore) Get(obj *types.CiliumEndpoint) (*types.CiliumEndpoint, bool, error) {
	panic("MockCiliumEndpointStore.Get not implemented")
}

func (m *MockCiliumEndpointStore) GetByKey(key resource.Key) (*types.CiliumEndpoint, bool, error) {
	panic("MockCiliumEndpointStore.GetByKey not implemented")
}

func (m *MockCiliumEndpointStore) ByIndex(index string, key string) ([]*types.CiliumEndpoint, error) {
	var result []*types.CiliumEndpoint
	for _, ep := range m.endpoints {
		if ep.Namespace == key {
			result = append(result, ep)
		}
	}
	return result, nil
}

func (m *MockCiliumEndpointStore) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("MockCiliumEndpointStore.IndexKeys not implemented")
}

func (m *MockCiliumEndpointStore) IterKeys() resource.KeyIter {
	panic("MockCiliumEndpointStore.IterKeys not implemented")
}

func (m *MockCiliumEndpointStore) CacheStore() cache.Store {
	panic("MockCiliumEndpointStore.CacheStore not implemented")
}

// MockCiliumEndpointSliceResource is a mock implementation of resource.Resource[*v2alpha1.CiliumEndpointSlice].
type MockCiliumEndpointSliceResource struct {
	store    *MockCiliumEndpointSliceStore
	storeErr error
}

func (m *MockCiliumEndpointSliceResource) Store(ctx context.Context) (resource.Store[*v2alpha1.CiliumEndpointSlice], error) {
	if m.storeErr != nil {
		return nil, m.storeErr
	}
	return m.store, nil
}

func (m *MockCiliumEndpointSliceResource) Observe(ctx context.Context, next func(resource.Event[*v2alpha1.CiliumEndpointSlice]), complete func(error)) {
	panic("MockCiliumEndpointSliceResource.Observe not implemented")
}

func (m *MockCiliumEndpointSliceResource) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*v2alpha1.CiliumEndpointSlice] {
	panic("MockCiliumEndpointSliceResource.Events not implemented")
}

// MockCiliumEndpointSliceStore is a mock implementation of resource.Store[*v2alpha1.CiliumEndpointSlice].
type MockCiliumEndpointSliceStore struct {
	slices map[string]*v2alpha1.CiliumEndpointSlice
}

func (m *MockCiliumEndpointSliceStore) List() []*v2alpha1.CiliumEndpointSlice {
	panic("MockCiliumEndpointSliceStore.List not implemented")
}

func (m *MockCiliumEndpointSliceStore) Get(key *v2alpha1.CiliumEndpointSlice) (*v2alpha1.CiliumEndpointSlice, bool, error) {
	panic("MockCiliumEndpointSliceStore.Get not implemented")
}

func (m *MockCiliumEndpointSliceStore) GetByKey(key resource.Key) (*v2alpha1.CiliumEndpointSlice, bool, error) {
	panic("MockCiliumEndpointStore.GetByKey not implemented")
}

func (m *MockCiliumEndpointSliceStore) ByIndex(index string, key string) ([]*v2alpha1.CiliumEndpointSlice, error) {
	var result []*v2alpha1.CiliumEndpointSlice
	for _, s := range m.slices {
		if s.Namespace == key {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *MockCiliumEndpointSliceStore) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("MockCiliumEndpointStore.IndexKeys not implemented")
}

func (m *MockCiliumEndpointSliceStore) IterKeys() resource.KeyIter {
	panic("MockCiliumEndpointStore.IterKeys not implemented")
}

func (m *MockCiliumEndpointSliceStore) CacheStore() cache.Store {
	panic("MockCiliumEndpointSliceStore.CacheStore not implemented")
}

var _ resource.Store[*types.CiliumEndpoint] = &MockCiliumEndpointStore{}
var _ resource.Store[*v2alpha1.CiliumEndpointSlice] = &MockCiliumEndpointSliceStore{}

// createTestEndpoint creates a test endpoint with the given parameters.
func createTestEndpoint(id uint16, namespace, podName, netnsPath string) *endpoint.Endpoint {
	return createTestEndpointWithLabels(id, namespace, podName, netnsPath, nil)
}

// createTestEndpointWithLabels creates a test endpoint with the given parameters and labels.
func createTestEndpointWithLabels(id uint16, namespace, podName, netnsPath string, lbls labels.Labels) *endpoint.Endpoint {
	ep := &endpoint.Endpoint{
		ID:           id,
		K8sNamespace: namespace,
		K8sPodName:   podName,
	}
	ep.SetContainerNetnsPath(netnsPath)
	if lbls != nil {
		ep.SecurityIdentity = identity.NewIdentity(identity.NumericIdentity(id), lbls)
	}
	return ep
}

// setupTest creates a test environment with mock dependencies and returns
// the database, table, mocks, and reconciler instance.
func setupTest(t *testing.T) (*statedb.DB, statedb.RWTable[*table.EnrolledNamespace], *MockEndpointManager, *MockEndpointEnroller, *EnrollmentReconciler, chan *xds.EndpointEvent) {
	db := statedb.New()
	tbl, err := table.NewEnrolledNamespacesTable(db)
	require.NoError(t, err)

	logger := hivetest.Logger(t)

	mockEpMgr := &MockEndpointManager{}
	mockEnroller := NewMockEndpointEnroller()
	endpointEventCh := make(chan *xds.EndpointEvent, 100)

	mockCEPResource := &MockCiliumEndpointResource{
		store: &MockCiliumEndpointStore{
			endpoints: make(map[string]*types.CiliumEndpoint),
		},
	}

	mockCESResource := &MockCiliumEndpointSliceResource{
		store: &MockCiliumEndpointSliceStore{
			slices: make(map[string]*v2alpha1.CiliumEndpointSlice),
		},
	}

	// Create a promise that resolves immediately with a mock restorer.
	restorer, restorerPromise := promise.New[endpointstate.Restorer]()
	restorer.Resolve(&MockRestorer{})

	// hivetest.Lifecycle automatically calls Start() when Append() is invoked,
	// and queues Stop() for test cleanup.
	lc := hivetest.Lifecycle(t)

	ops := NewEnrollmentReconciler(params{
		Config:                      config.Config{EnableZTunnel: true},
		DB:                          db,
		EnrolledNamespaceTable:      tbl,
		Logger:                      logger,
		Lifecycle:                   lc,
		EndpointManager:             mockEpMgr,
		EndpointEnroller:            mockEnroller,
		RestorerPromise:             restorerPromise,
		EndpointEventChannel:        endpointEventCh,
		CiliumEndpointResource:      mockCEPResource,
		CiliumEndpointSliceResource: mockCESResource,
	})

	reconcilerOps := ops.(*EnrollmentReconciler)

	return db, tbl, mockEpMgr, mockEnroller, reconcilerOps, endpointEventCh
}

// TestEnrollmentReconciler_Update tests the Update operation of the reconciler,
// which enrolls all endpoints in a namespace when that namespace is enrolled.
func TestEnrollmentReconciler_Update(t *testing.T) {
	tests := []struct {
		name                      string
		namespace                 string
		endpoints                 []*endpoint.Endpoint
		enableCiliumEndpointSlice bool
		ciliumEndpoints           map[string]*types.CiliumEndpoint
		ciliumEndpointSlices      map[string]*v2alpha1.CiliumEndpointSlice
		enrollErr                 error
		expectedEnrolled          int
		expectedEndpointEvents    int
		expectedError             bool
	}{
		{
			name:      "enroll endpoints in namespace",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", "/var/run/netns/test2"),
			},
			expectedEnrolled:       2,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip endpoints without netns path",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", ""),
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip ztunnel endpoints",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpointWithLabels(2, "test-ns", "ztunnel-cilium-abc", "/var/run/netns/test2", labels.Labels{
					"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
				}),
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "enrollment error",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			enrollErr:              errors.New("enrollment failed"),
			expectedEnrolled:       0,
			expectedEndpointEvents: 0,
			expectedError:          true,
		},
		{
			name:             "no endpoints in namespace",
			namespace:        "empty-ns",
			endpoints:        []*endpoint.Endpoint{},
			expectedEnrolled: 0,
			expectedError:    false,
		},
		{
			name:                   "no endpoints in namespace",
			namespace:              "empty-ns",
			endpoints:              []*endpoint.Endpoint{},
			expectedEnrolled:       0,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:                      "enroll with CiliumEndpoint resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: false,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpoints: map[string]*types.CiliumEndpoint{
				"test-ns/cep-1": {
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "cep-1",
						Namespace: "test-ns",
					},
				},
				"test-ns/cep-2": {
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "cep-2",
						Namespace: "test-ns",
					},
				},
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 2,
			expectedError:          false,
		},
		{
			name:                      "enroll with CiliumEndpointSlice resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: true,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpointSlices: map[string]*v2alpha1.CiliumEndpointSlice{
				"test-ns/ces-1": {
					ObjectMeta: v1.ObjectMeta{
						Name: "ces-1",
					},
					Namespace: "test-ns",
					Endpoints: []v2alpha1.CoreCiliumEndpoint{
						{
							Name: "pod-1",
						},
						{
							Name: "pod-2",
						},
					},
				},
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 2,
			expectedError:          false,
		},
		{
			name:                      "enroll with multiple CiliumEndpointSlices",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: true,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpointSlices: map[string]*v2alpha1.CiliumEndpointSlice{
				"test-ns/ces-1": {
					ObjectMeta: v1.ObjectMeta{
						Name: "ces-1",
					},
					Namespace: "test-ns",
					Endpoints: []v2alpha1.CoreCiliumEndpoint{
						{Name: "pod-1"},
						{Name: "pod-2"},
					},
				},
				"test-ns/ces-2": {
					ObjectMeta: v1.ObjectMeta{
						Name: "ces-2",
					},
					Namespace: "test-ns",
					Endpoints: []v2alpha1.CoreCiliumEndpoint{
						{Name: "pod-3"},
					},
				},
			},
			expectedEnrolled:       1,
			expectedEndpointEvents: 3,
			expectedError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore the original option value
			originalEnableCES := option.Config.EnableCiliumEndpointSlice
			defer func() {
				option.Config.EnableCiliumEndpointSlice = originalEnableCES
			}()
			option.Config.EnableCiliumEndpointSlice = tt.enableCiliumEndpointSlice
			db, _, mockEpMgr, mockEnroller, ops, endpointEventCh := setupTest(t)

			// Setup CiliumEndpoint or CiliumEndpointSlice resources
			if tt.ciliumEndpoints != nil {
				mockCEPStore := ops.ciliumEndpointResource.(*MockCiliumEndpointResource).store
				mockCEPStore.endpoints = tt.ciliumEndpoints
			}
			if tt.ciliumEndpointSlices != nil {
				mockCESStore := ops.ciliumEndpointSliceResource.(*MockCiliumEndpointSliceResource).store
				mockCESStore.slices = tt.ciliumEndpointSlices
			}

			mockEpMgr.endpoints = tt.endpoints
			mockEnroller.enrollErr = tt.enrollErr

			ns := &table.EnrolledNamespace{
				Name:   tt.namespace,
				Status: reconciler.StatusPending(),
			}

			err := ops.Update(context.Background(), db.ReadTxn(), 1, ns)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, mockEnroller.enrolledEndpoints, tt.expectedEnrolled)

			// Verify endpoint events were sent
			eventCount := 0
			timeout := time.After(100 * time.Millisecond)
		drainLoop:
			for {
				select {
				case event := <-endpointEventCh:
					eventCount++
					assert.Equal(t, xds.CREATE, event.Type)
				case <-timeout:
					break drainLoop
				default:
					if eventCount >= tt.expectedEndpointEvents {
						break drainLoop
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			assert.Equal(t, tt.expectedEndpointEvents, eventCount, "unexpected number of endpoint events")
		})
	}
}

func TestEnrollmentReconciler_Update_StoreErrors(t *testing.T) {
	t.Run("CEP store error returns error", func(t *testing.T) {
		originalEnableCES := option.Config.EnableCiliumEndpointSlice
		defer func() { option.Config.EnableCiliumEndpointSlice = originalEnableCES }()
		option.Config.EnableCiliumEndpointSlice = false

		db, _, _, _, ops, _ := setupTest(t)

		// Inject store error
		ops.ciliumEndpointResource.(*MockCiliumEndpointResource).storeErr = errors.New("store unavailable")

		ns := &table.EnrolledNamespace{
			Name:   "test-ns",
			Status: reconciler.StatusPending(),
		}

		err := ops.Update(context.Background(), db.ReadTxn(), 1, ns)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get CiliumEndpoint store")
	})

	t.Run("CES store error returns error", func(t *testing.T) {
		originalEnableCES := option.Config.EnableCiliumEndpointSlice
		defer func() { option.Config.EnableCiliumEndpointSlice = originalEnableCES }()
		option.Config.EnableCiliumEndpointSlice = true

		db, _, _, _, ops, _ := setupTest(t)

		// Inject store error
		ops.ciliumEndpointSliceResource.(*MockCiliumEndpointSliceResource).storeErr = errors.New("store unavailable")

		ns := &table.EnrolledNamespace{
			Name:   "test-ns",
			Status: reconciler.StatusPending(),
		}

		err := ops.Update(context.Background(), db.ReadTxn(), 1, ns)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get CiliumEndpointSlice store")
	})
}

func TestEnrollmentReconciler_Delete_StoreErrors(t *testing.T) {
	t.Run("CEP store error returns error", func(t *testing.T) {
		originalEnableCES := option.Config.EnableCiliumEndpointSlice
		defer func() { option.Config.EnableCiliumEndpointSlice = originalEnableCES }()
		option.Config.EnableCiliumEndpointSlice = false

		db, _, _, _, ops, _ := setupTest(t)

		// Inject store error
		ops.ciliumEndpointResource.(*MockCiliumEndpointResource).storeErr = errors.New("store unavailable")

		ns := &table.EnrolledNamespace{
			Name:   "test-ns",
			Status: reconciler.StatusPending(),
		}

		err := ops.Delete(context.Background(), db.ReadTxn(), 1, ns)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get CiliumEndpoint store")
	})

	t.Run("CES store error returns error", func(t *testing.T) {
		originalEnableCES := option.Config.EnableCiliumEndpointSlice
		defer func() { option.Config.EnableCiliumEndpointSlice = originalEnableCES }()
		option.Config.EnableCiliumEndpointSlice = true

		db, _, _, _, ops, _ := setupTest(t)

		// Inject store error
		ops.ciliumEndpointSliceResource.(*MockCiliumEndpointSliceResource).storeErr = errors.New("store unavailable")

		ns := &table.EnrolledNamespace{
			Name:   "test-ns",
			Status: reconciler.StatusPending(),
		}

		err := ops.Delete(context.Background(), db.ReadTxn(), 1, ns)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get CiliumEndpointSlice store")
	})
}

// TestEnrollmentReconciler_Delete tests the Delete operation of the reconciler,
// which disenrolls all endpoints in a namespace when that namespace is unenrolled.
func TestEnrollmentReconciler_Delete(t *testing.T) {
	tests := []struct {
		name                      string
		namespace                 string
		endpoints                 []*endpoint.Endpoint
		enableCiliumEndpointSlice bool
		ciliumEndpoints           map[string]*types.CiliumEndpoint
		ciliumEndpointSlices      map[string]*v2alpha1.CiliumEndpointSlice
		disenrollErr              error
		expectedDisenrolled       int
		expectedEndpointEvents    int
		expectedError             bool
	}{
		{
			name:      "disenroll endpoints in namespace",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", "/var/run/netns/test2"),
			},
			expectedDisenrolled:    2,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip endpoints without netns path",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", ""),
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "skip ztunnel endpoints",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpointWithLabels(2, "test-ns", "ztunnel-cilium-xyz", "/var/run/netns/test2", labels.Labels{
					"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
				}),
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 0,
			expectedError:          false,
		},
		{
			name:      "disenrollment error",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			disenrollErr:           errors.New("disenrollment failed"),
			expectedDisenrolled:    0,
			expectedEndpointEvents: 0,
			expectedError:          true,
		},
		{
			name:                      "disenroll with CiliumEndpoint resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: false,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpoints: map[string]*types.CiliumEndpoint{
				"test-ns/cep-1": {
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "cep-1",
						Namespace: "test-ns",
					},
				},
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 1,
			expectedError:          false,
		},
		{
			name:                      "disenroll with CiliumEndpointSlice resources",
			namespace:                 "test-ns",
			enableCiliumEndpointSlice: true,
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			ciliumEndpointSlices: map[string]*v2alpha1.CiliumEndpointSlice{
				"test-ns/ces-1": {
					ObjectMeta: v1.ObjectMeta{
						Name: "ces-1",
					},
					Namespace: "test-ns",
					Endpoints: []v2alpha1.CoreCiliumEndpoint{
						{Name: "pod-1"},
						{Name: "pod-2"},
					},
				},
			},
			expectedDisenrolled:    1,
			expectedEndpointEvents: 2,
			expectedError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore the original option value
			originalEnableCES := option.Config.EnableCiliumEndpointSlice
			defer func() {
				option.Config.EnableCiliumEndpointSlice = originalEnableCES
			}()
			option.Config.EnableCiliumEndpointSlice = tt.enableCiliumEndpointSlice
			db, _, mockEpMgr, mockEnroller, ops, endpointEventCh := setupTest(t)

			mockEpMgr.endpoints = tt.endpoints
			mockEnroller.disenrollErr = tt.disenrollErr

			// Setup CiliumEndpoint or CiliumEndpointSlice resources
			if tt.ciliumEndpoints != nil {
				mockCEPStore := ops.ciliumEndpointResource.(*MockCiliumEndpointResource).store
				mockCEPStore.endpoints = tt.ciliumEndpoints
			}
			if tt.ciliumEndpointSlices != nil {
				mockCESStore := ops.ciliumEndpointSliceResource.(*MockCiliumEndpointSliceResource).store
				mockCESStore.slices = tt.ciliumEndpointSlices
			}

			ns := &table.EnrolledNamespace{
				Name:   tt.namespace,
				Status: reconciler.StatusPending(),
			}

			err := ops.Delete(context.Background(), db.ReadTxn(), 1, ns)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, mockEnroller.disenrolledIDs, tt.expectedDisenrolled)
			}

			// Verify endpoint events were sent
			eventCount := 0
			timeout := time.After(100 * time.Millisecond)
		drainLoop:
			for {
				select {
				case event := <-endpointEventCh:
					eventCount++
					assert.Equal(t, xds.REMOVED, event.Type)
				case <-timeout:
					break drainLoop
				default:
					if eventCount >= tt.expectedEndpointEvents {
						break drainLoop
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			assert.Equal(t, tt.expectedEndpointEvents, eventCount, "unexpected number of endpoint events")
		})
	}
}

// TestEnrollmentReconciler_EndpointCreated tests the EndpointCreated event handler,
// which enrolls newly created endpoints if their namespace is enrolled.
func TestEnrollmentReconciler_EndpointCreated(t *testing.T) {
	tests := []struct {
		name             string
		endpoint         *endpoint.Endpoint
		enrolledNs       []string
		enrollErr        error
		expectedEnrolled bool
	}{
		{
			name:             "enroll endpoint in enrolled namespace",
			endpoint:         createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: true,
		},
		{
			name:             "skip endpoint in unenrolled namespace",
			endpoint:         createTestEndpoint(1, "other-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
		{
			name:             "skip endpoint without netns path",
			endpoint:         createTestEndpoint(1, "test-ns", "pod-1", ""),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
		{
			name: "skip ztunnel endpoint",
			endpoint: createTestEndpointWithLabels(1, "test-ns", "ztunnel-cilium-abc", "/var/run/netns/test1", labels.Labels{
				"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
			}),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
		{
			name:             "skip endpoint without namespace",
			endpoint:         createTestEndpoint(1, "", "pod-1", "/var/run/netns/test1"),
			enrolledNs:       []string{"test-ns"},
			expectedEnrolled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, tbl, _, mockEnroller, ops, _ := setupTest(t)

			mockEnroller.enrollErr = tt.enrollErr

			// Initialize table and add enrolled namespaces.
			txn := db.WriteTxn(tbl)
			complete := tbl.RegisterInitializer(txn, "test")
			for _, ns := range tt.enrolledNs {
				tbl.Insert(txn, &table.EnrolledNamespace{
					Name:   ns,
					Status: reconciler.StatusPending(),
				})
			}
			complete(txn)
			txn.Commit()

			// Clear any enrollments from initialization.
			mockEnroller.enrolledEndpoints = make(map[uint16]*endpoint.Endpoint)

			// Trigger endpoint created event.
			ops.EndpointCreated(tt.endpoint)

			// EndpointCreated is synchronous, but we add a small delay for safety.
			time.Sleep(50 * time.Millisecond)

			if tt.expectedEnrolled {
				assert.Contains(t, mockEnroller.enrolledEndpoints, tt.endpoint.ID)
			} else {
				assert.NotContains(t, mockEnroller.enrolledEndpoints, tt.endpoint.ID)
			}
		})
	}
}

// TestEnrollmentReconciler_EndpointDeleted tests the EndpointDeleted event handler,
// which disenrolls deleted endpoints if their namespace is enrolled.
func TestEnrollmentReconciler_EndpointDeleted(t *testing.T) {
	tests := []struct {
		name                string
		endpoint            *endpoint.Endpoint
		enrolledNs          []string
		expectedDisenrolled bool
	}{
		{
			name:                "disenroll endpoint in enrolled namespace",
			endpoint:            createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: true,
		},
		{
			name:                "skip endpoint in unenrolled namespace",
			endpoint:            createTestEndpoint(1, "other-ns", "pod-1", "/var/run/netns/test1"),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: false,
		},
		{
			name:                "skip endpoint without netns path",
			endpoint:            createTestEndpoint(1, "test-ns", "pod-1", ""),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: false,
		},
		{
			name: "skip ztunnel endpoint",
			endpoint: createTestEndpointWithLabels(1, "test-ns", "ztunnel-cilium-xyz", "/var/run/netns/test1", labels.Labels{
				"k8s:app": labels.NewLabel("app", "ztunnel-cilium", labels.LabelSourceK8s),
			}),
			enrolledNs:          []string{"test-ns"},
			expectedDisenrolled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, tbl, _, mockEnroller, ops, _ := setupTest(t)

			// Initialize table and add enrolled namespaces.
			txn := db.WriteTxn(tbl)
			complete := tbl.RegisterInitializer(txn, "test")
			for _, ns := range tt.enrolledNs {
				tbl.Insert(txn, &table.EnrolledNamespace{
					Name:   ns,
					Status: reconciler.StatusPending(),
				})
			}
			complete(txn)
			txn.Commit()

			// Clear disenrollment tracking.
			mockEnroller.disenrolledIDs = []uint16{}

			// Trigger endpoint deleted event.
			ops.EndpointDeleted(tt.endpoint, endpoint.DeleteConfig{})

			// EndpointDeleted is synchronous, but we add a small delay for safety.
			time.Sleep(50 * time.Millisecond)

			if tt.expectedDisenrolled {
				assert.Contains(t, mockEnroller.disenrolledIDs, tt.endpoint.ID)
			} else {
				assert.NotContains(t, mockEnroller.disenrolledIDs, tt.endpoint.ID)
			}
		})
	}
}
