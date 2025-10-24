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

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/table"
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
func setupTest(t *testing.T) (*statedb.DB, statedb.RWTable[*table.EnrolledNamespace], *MockEndpointManager, *MockEndpointEnroller, *EnrollmentReconciler) {
	db := statedb.New()
	tbl, err := table.NewEnrolledNamespacesTable(db)
	require.NoError(t, err)

	logger := hivetest.Logger(t)

	mockEpMgr := &MockEndpointManager{}
	mockEnroller := NewMockEndpointEnroller()

	// Create a promise that resolves immediately with a mock restorer.
	restorer, restorerPromise := promise.New[endpointstate.Restorer]()
	restorer.Resolve(&MockRestorer{})

	// hivetest.Lifecycle automatically calls Start() when Append() is invoked,
	// and queues Stop() for test cleanup.
	lc := hivetest.Lifecycle(t)

	ops := NewEnrollmentReconciler(params{
		Config:                 config.Config{EnableZTunnel: true},
		DB:                     db,
		EnrolledNamespaceTable: tbl,
		Logger:                 logger,
		Lifecycle:              lc,
		EndpointManager:        mockEpMgr,
		EndpointEnroller:       mockEnroller,
		RestorerPromise:        restorerPromise,
	})

	reconcilerOps := ops.(*EnrollmentReconciler)

	return db, tbl, mockEpMgr, mockEnroller, reconcilerOps
}

// TestEnrollmentReconciler_Update tests the Update operation of the reconciler,
// which enrolls all endpoints in a namespace when that namespace is enrolled.
func TestEnrollmentReconciler_Update(t *testing.T) {
	tests := []struct {
		name             string
		namespace        string
		endpoints        []*endpoint.Endpoint
		enrollErr        error
		expectedEnrolled int
		expectedError    bool
	}{
		{
			name:      "enroll endpoints in namespace",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", "/var/run/netns/test2"),
			},
			expectedEnrolled: 2,
			expectedError:    false,
		},
		{
			name:      "skip endpoints without netns path",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", ""),
			},
			expectedEnrolled: 1,
			expectedError:    false,
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
			expectedEnrolled: 1,
			expectedError:    false,
		},
		{
			name:      "enrollment error",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			enrollErr:        errors.New("enrollment failed"),
			expectedEnrolled: 0,
			expectedError:    true,
		},
		{
			name:             "no endpoints in namespace",
			namespace:        "empty-ns",
			endpoints:        []*endpoint.Endpoint{},
			expectedEnrolled: 0,
			expectedError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _, mockEpMgr, mockEnroller, ops := setupTest(t)

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
		})
	}
}

// TestEnrollmentReconciler_Delete tests the Delete operation of the reconciler,
// which disenrolls all endpoints in a namespace when that namespace is unenrolled.
func TestEnrollmentReconciler_Delete(t *testing.T) {
	tests := []struct {
		name                string
		namespace           string
		endpoints           []*endpoint.Endpoint
		disenrollErr        error
		expectedDisenrolled int
		expectedError       bool
	}{
		{
			name:      "disenroll endpoints in namespace",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", "/var/run/netns/test2"),
			},
			expectedDisenrolled: 2,
			expectedError:       false,
		},
		{
			name:      "skip endpoints without netns path",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
				createTestEndpoint(2, "test-ns", "pod-2", ""),
			},
			expectedDisenrolled: 1,
			expectedError:       false,
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
			expectedDisenrolled: 1,
			expectedError:       false,
		},
		{
			name:      "disenrollment error",
			namespace: "test-ns",
			endpoints: []*endpoint.Endpoint{
				createTestEndpoint(1, "test-ns", "pod-1", "/var/run/netns/test1"),
			},
			disenrollErr:        errors.New("disenrollment failed"),
			expectedDisenrolled: 0,
			expectedError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _, mockEpMgr, mockEnroller, ops := setupTest(t)

			mockEpMgr.endpoints = tt.endpoints
			mockEnroller.disenrollErr = tt.disenrollErr

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
			db, tbl, _, mockEnroller, ops := setupTest(t)

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
			db, tbl, _, mockEnroller, ops := setupTest(t)

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
