// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

func newTestK8sNamespace(name string, labels map[string]string) k8sTables.Namespace {
	return k8sTables.Namespace{
		Name:   name,
		Labels: labels,
	}
}

// mockSpireClient implements SpireClient for testing.
type mockSpireClient struct {
	upsertBatchFunc func(ctx context.Context, ids []string) error
	deleteBatchFunc func(ctx context.Context, ids []string) error
	upsertFunc      func(ctx context.Context, id string) error
	deleteFunc      func(ctx context.Context, id string) error
	initialized     chan struct{}
}

func newMockSpireClient() *mockSpireClient {
	ch := make(chan struct{})
	close(ch)
	return &mockSpireClient{
		initialized: ch,
	}
}

func (m *mockSpireClient) UpsertBatch(ctx context.Context, ids []string) error {
	if m.upsertBatchFunc != nil {
		return m.upsertBatchFunc(ctx, ids)
	}
	return nil
}

func (m *mockSpireClient) DeleteBatch(ctx context.Context, ids []string) error {
	if m.deleteBatchFunc != nil {
		return m.deleteBatchFunc(ctx, ids)
	}
	return nil
}

func (m *mockSpireClient) Upsert(ctx context.Context, id string) error {
	if m.upsertFunc != nil {
		return m.upsertFunc(ctx, id)
	}
	return nil
}

func (m *mockSpireClient) Delete(ctx context.Context, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	return nil
}

func (m *mockSpireClient) Initialized() <-chan struct{} {
	return m.initialized
}

func setupTest(t *testing.T) (*statedb.DB, statedb.RWTable[*table.EnrolledNamespace], statedb.RWTable[ServiceAccount], *mockSpireClient, *EnrollmentReconciler) {
	db := statedb.New()

	enrolledTbl, err := table.NewEnrolledNamespacesTable(db)
	require.NoError(t, err)

	saTbl, err := statedb.NewTable(db, "serviceaccounts",
		ServiceAccountNamespacedNameIndex,
		ServiceAccountNamespaceIndex,
	)
	require.NoError(t, err)

	mock := newMockSpireClient()
	logger := hivetest.Logger(t)

	ops := &EnrollmentReconciler{
		db:                     db,
		logger:                 logger,
		spireClient:            mock,
		serviceAccountTable:    saTbl,
		enrolledNamespaceTable: enrolledTbl,
		metrics:                NewMetrics(),
	}

	return db, enrolledTbl, saTbl, mock, ops
}

func insertServiceAccounts(_ *testing.T, db *statedb.DB, saTbl statedb.RWTable[ServiceAccount], namespace string, names ...string) {
	txn := db.WriteTxn(saTbl)
	for _, name := range names {
		saTbl.Insert(txn, ServiceAccount{
			ServiceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
			},
		})
	}
	txn.Commit()
}

// getMetric reads the current value of a counter with the given label values.
func getMetric(m *Metrics, method, outcome string) float64 {
	return m.EnrollmentOps.WithLabelValues(method, outcome).Get()
}

func TestEnrollmentReconciler_Update(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		saNames       []string
		upsertErr     error
		wantErr       bool
		wantUpsertIDs []string
	}{
		{
			name:          "upserts service accounts in namespace",
			namespace:     "test-ns",
			saNames:       []string{"sa1", "sa2"},
			wantErr:       false,
			wantUpsertIDs: []string{"test-ns/sa1", "test-ns/sa2"},
		},
		{
			name:      "upsert batch error",
			namespace: "test-ns",
			saNames:   []string{"sa1"},
			upsertErr: fmt.Errorf("spire server unavailable"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _, saTbl, mock, ops := setupTest(t)

			if len(tt.saNames) > 0 {
				insertServiceAccounts(t, db, saTbl, tt.namespace, tt.saNames...)
			}

			var gotIDs []string
			mock.upsertBatchFunc = func(ctx context.Context, ids []string) error {
				gotIDs = ids
				return tt.upsertErr
			}

			ns := &table.EnrolledNamespace{
				Name:   tt.namespace,
				Status: reconciler.StatusPending(),
			}
			err := ops.Update(t.Context(), db.ReadTxn(), 0, ns)

			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, float64(len(tt.saNames)),
					getMetric(ops.metrics, LabelValueMethodUpsert, LabelValueOutcomeFail))
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, tt.wantUpsertIDs, gotIDs)
				require.Equal(t, float64(len(tt.saNames)),
					getMetric(ops.metrics, LabelValueMethodUpsert, LabelValueOutcomeSuccess))
			}
		})
	}
}

func TestEnrollmentReconciler_Delete(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		saNames       []string
		deleteErr     error
		wantErr       bool
		wantDeleteIDs []string
	}{
		{
			name:          "deletes service accounts in namespace",
			namespace:     "test-ns",
			saNames:       []string{"sa1", "sa2"},
			wantErr:       false,
			wantDeleteIDs: []string{"test-ns/sa1", "test-ns/sa2"},
		},
		{
			name:      "delete batch error",
			namespace: "test-ns",
			saNames:   []string{"sa1"},
			deleteErr: fmt.Errorf("spire server unavailable"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _, saTbl, mock, ops := setupTest(t)

			if len(tt.saNames) > 0 {
				insertServiceAccounts(t, db, saTbl, tt.namespace, tt.saNames...)
			}

			var gotIDs []string
			mock.deleteBatchFunc = func(ctx context.Context, ids []string) error {
				gotIDs = ids
				return tt.deleteErr
			}

			ns := &table.EnrolledNamespace{
				Name:   tt.namespace,
				Status: reconciler.StatusPending(),
			}
			err := ops.Delete(t.Context(), db.ReadTxn(), 0, ns)

			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, float64(len(tt.saNames)),
					getMetric(ops.metrics, LabelValueMethodDelete, LabelValueOutcomeFail))
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, tt.wantDeleteIDs, gotIDs)
				require.Equal(t, float64(len(tt.saNames)),
					getMetric(ops.metrics, LabelValueMethodDelete, LabelValueOutcomeSuccess))
			}
		})
	}
}

func TestEnrollmentReconciler_Update_OnlyIncludesMatchingNamespace(t *testing.T) {
	db, _, saTbl, mock, ops := setupTest(t)

	// Insert SAs in two different namespaces.
	insertServiceAccounts(t, db, saTbl, "enrolled-ns", "sa1", "sa2")
	insertServiceAccounts(t, db, saTbl, "other-ns", "sa3")

	var gotIDs []string
	mock.upsertBatchFunc = func(ctx context.Context, ids []string) error {
		gotIDs = ids
		return nil
	}

	// Update should only include SAs from "enrolled-ns".
	ns := &table.EnrolledNamespace{
		Name:   "enrolled-ns",
		Status: reconciler.StatusPending(),
	}
	err := ops.Update(t.Context(), db.ReadTxn(), 0, ns)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"enrolled-ns/sa1", "enrolled-ns/sa2"}, gotIDs)
}

// initializeTables marks both SA and enrolled namespace tables as initialized
// so that Start() can proceed past its initialization checks.
func initializeTables(db *statedb.DB, saTbl statedb.RWTable[ServiceAccount], enrolledTbl statedb.RWTable[*table.EnrolledNamespace]) {
	txn := db.WriteTxn(saTbl, enrolledTbl)
	completeSA := saTbl.RegisterInitializer(txn, "test")
	completeNS := enrolledTbl.RegisterInitializer(txn, "test")
	completeSA(txn)
	completeNS(txn)
	txn.Commit()
}

func enrollNamespace(db *statedb.DB, enrolledTbl statedb.RWTable[*table.EnrolledNamespace], name string) {
	txn := db.WriteTxn(enrolledTbl)
	enrolledTbl.Insert(txn, &table.EnrolledNamespace{
		Name:   name,
		Status: reconciler.StatusPending(),
	})
	txn.Commit()
}

func deleteServiceAccount(db *statedb.DB, saTbl statedb.RWTable[ServiceAccount], namespace, name string) {
	txn := db.WriteTxn(saTbl)
	saTbl.Delete(txn, ServiceAccount{
		ServiceAccount: &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		},
	})
	txn.Commit()
}

func TestEnrollmentReconciler_Start_UpsertOnSACreate(t *testing.T) {
	db, enrolledTbl, saTbl, mock, ops := setupTest(t)
	initializeTables(db, saTbl, enrolledTbl)

	// Enroll a namespace before starting.
	enrollNamespace(db, enrolledTbl, "enrolled-ns")

	upserted := make(chan string, 10)
	mock.upsertFunc = func(_ context.Context, id string) error {
		upserted <- id
		return nil
	}

	require.NoError(t, ops.Start(t.Context()))
	defer ops.Stop(nil)

	// Add a service account in the enrolled namespace.
	insertServiceAccounts(t, db, saTbl, "enrolled-ns", "sa1")

	select {
	case id := <-upserted:
		require.Equal(t, "enrolled-ns/sa1", id)
		require.Eventually(t, func() bool {
			return getMetric(ops.metrics, LabelValueMethodUpsert, LabelValueOutcomeSuccess) == 1
		}, 5*time.Second, 10*time.Millisecond)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upsert")
	}
}

func TestEnrollmentReconciler_Start_SkipNonEnrolledNamespace(t *testing.T) {
	db, enrolledTbl, saTbl, mock, ops := setupTest(t)
	initializeTables(db, saTbl, enrolledTbl)

	// Enroll "enrolled-ns" but NOT "other-ns".
	enrollNamespace(db, enrolledTbl, "enrolled-ns")

	upserted := make(chan string, 10)
	mock.upsertFunc = func(_ context.Context, id string) error {
		upserted <- id
		return nil
	}

	require.NoError(t, ops.Start(t.Context()))
	defer ops.Stop(nil)

	// Add a service account in the non-enrolled namespace first.
	insertServiceAccounts(t, db, saTbl, "other-ns", "sa1")

	// Then add one in the enrolled namespace. When we see this upsert,
	// we know the watcher has processed past the non-enrolled SA.
	insertServiceAccounts(t, db, saTbl, "enrolled-ns", "sentinel")

	select {
	case id := <-upserted:
		require.Equal(t, "enrolled-ns/sentinel", id, "only the enrolled namespace SA should be upserted")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sentinel upsert")
	}
}

func TestEnrollmentReconciler_Start_DeleteOnSARemove(t *testing.T) {
	db, enrolledTbl, saTbl, mock, ops := setupTest(t)
	initializeTables(db, saTbl, enrolledTbl)

	enrollNamespace(db, enrolledTbl, "enrolled-ns")

	// Pre-populate a SA so we can delete it.
	insertServiceAccounts(t, db, saTbl, "enrolled-ns", "sa1")

	upserted := make(chan string, 10)
	deleted := make(chan string, 10)
	mock.upsertFunc = func(_ context.Context, id string) error {
		upserted <- id
		return nil
	}
	mock.deleteFunc = func(_ context.Context, id string) error {
		deleted <- id
		return nil
	}

	require.NoError(t, ops.Start(t.Context()))
	defer ops.Stop(nil)

	// Wait for the initial SA creation to be processed.
	select {
	case <-upserted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial upsert")
	}

	// Now delete the SA.
	deleteServiceAccount(db, saTbl, "enrolled-ns", "sa1")

	select {
	case id := <-deleted:
		require.Equal(t, "enrolled-ns/sa1", id)
		require.Eventually(t, func() bool {
			return getMetric(ops.metrics, LabelValueMethodDelete, LabelValueOutcomeSuccess) == 1
		}, 5*time.Second, 10*time.Millisecond)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for delete")
	}
}

func TestEnrollmentReconciler_Start_ErrorMetricsAndRequeue(t *testing.T) {
	db, enrolledTbl, saTbl, mock, ops := setupTest(t)
	initializeTables(db, saTbl, enrolledTbl)

	enrollNamespace(db, enrolledTbl, "enrolled-ns")

	upsertCalled := make(chan struct{}, 10)
	mock.upsertFunc = func(_ context.Context, id string) error {
		upsertCalled <- struct{}{}
		return fmt.Errorf("spire unavailable")
	}

	require.NoError(t, ops.Start(t.Context()))
	defer ops.Stop(nil)

	// Add a SA — upsert should be called even though it errors.
	insertServiceAccounts(t, db, saTbl, "enrolled-ns", "sa1")

	select {
	case <-upsertCalled:
		require.Eventually(t, func() bool {
			return getMetric(ops.metrics, LabelValueMethodUpsert, LabelValueOutcomeFail) == 1
		}, 5*time.Second, 10*time.Millisecond)

		// Verify the namespace was requeued to pending for re-reconciliation.
		require.Eventually(t, func() bool {
			ns, _, found := enrolledTbl.Get(db.ReadTxn(), table.EnrolledNamespacesNameIndex.Query("enrolled-ns"))
			return found && ns.Status.Kind == reconciler.StatusKindPending
		}, 5*time.Second, 10*time.Millisecond)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upsert call")
	}
}

func TestEnrollmentReconciler_Start_WaitsForSpireInit(t *testing.T) {
	db, enrolledTbl, saTbl, _, ops := setupTest(t)
	initializeTables(db, saTbl, enrolledTbl)

	enrollNamespace(db, enrolledTbl, "enrolled-ns")

	// Create a mock with uninitialized SPIRE client.
	spireInitCh := make(chan struct{})
	mock := &mockSpireClient{
		initialized: spireInitCh,
	}
	upserted := make(chan string, 10)
	mock.upsertFunc = func(_ context.Context, id string) error {
		upserted <- id
		return nil
	}
	ops.spireClient = mock

	require.NoError(t, ops.Start(t.Context()))
	defer ops.Stop(nil)

	// Add a SA before SPIRE is initialized.
	insertServiceAccounts(t, db, saTbl, "enrolled-ns", "sa1")

	// Verify that no upsert happens while SPIRE is not initialized.
	select {
	case id := <-upserted:
		t.Fatalf("unexpected upsert before SPIRE init: %s", id)
	case <-time.After(200 * time.Millisecond):
		// Expected.
	}

	// Now initialize SPIRE.
	close(spireInitCh)

	// The SA change should be processed now.
	select {
	case id := <-upserted:
		require.Equal(t, "enrolled-ns/sa1", id)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upsert after SPIRE init")
	}
}

func TestK8sNamespaceToEnrolledNamespace_LabelMatching(t *testing.T) {
	tests := []struct {
		name       string
		labels     map[string]string
		deleted    bool
		wantResult statedb.DeriveResult
	}{
		{
			name:       "enrolled namespace",
			labels:     map[string]string{"io.cilium/mtls-enabled": "true"},
			wantResult: statedb.DeriveInsert,
		},
		{
			name:       "not enrolled - label missing",
			labels:     map[string]string{},
			wantResult: statedb.DeriveDelete,
		},
		{
			name:       "enrolled but deleted",
			labels:     map[string]string{"io.cilium/mtls-enabled": "true"},
			deleted:    true,
			wantResult: statedb.DeriveDelete,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := newTestK8sNamespace(tt.name, tt.labels)
			_, result := table.K8sNamespaceToEnrolledNamespace(ns, tt.deleted)
			require.Equal(t, tt.wantResult, result)
		})
	}
}
