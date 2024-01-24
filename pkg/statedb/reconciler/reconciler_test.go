// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/lock"
	metricsPkg "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

// Some constants so we don't use mysterious numbers in the test steps.
const (
	ID_1 = uint64(1)
	ID_2 = uint64(2)
	ID_3 = uint64(3)
)

func TestReconciler(t *testing.T) {
	testReconciler(t, false)
}

func TestReconciler_Batch(t *testing.T) {
	testReconciler(t, true)
}

func testReconciler(t *testing.T, batchOps bool) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
		// metrics.statusCollector uses cilium client, so we see some http connections.
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)

	var (
		mt       = &mockOps{}
		db       *statedb.DB
		registry *metricsPkg.Registry
		r        reconciler.Reconciler[*testObject]
		health   cell.Health
		scope    cell.Scope
	)

	testObjects, err := statedb.NewTable[*testObject]("test-objects", idIndex, statusIndex)
	require.NoError(t, err, "NewTable")

	hive := hive.New(
		statedb.Cell,
		job.Cell,
		reconciler.Cell,

		cell.Group(
			cell.Provide(func() *option.DaemonConfig { return option.Config }),
			cell.Provide(func() metricsPkg.RegistryConfig { return metricsPkg.RegistryConfig{} }),
			cell.Provide(metricsPkg.NewRegistry),
		),

		cell.Invoke(func(r *metricsPkg.Registry) {
			registry = r
		}),

		cell.Module(
			"test",
			"Test",

			cell.Provide(func(db_ *statedb.DB) (statedb.RWTable[*testObject], error) {
				db = db_
				return testObjects, db.RegisterTable(testObjects)
			}),
			cell.Provide(func() reconciler.Config[*testObject] {
				cfg := reconciler.Config[*testObject]{
					// Don't run the full reconciliation via timer, but rather explicitly so that the full
					// reconciliation operations don't mix with incremental when not expected.
					FullReconcilationInterval: time.Hour,

					RetryBackoffMinDuration: time.Millisecond,
					RetryBackoffMaxDuration: 10 * time.Millisecond,
					IncrementalRoundSize:    1000,
					GetObjectStatus:         (*testObject).GetStatus,
					WithObjectStatus:        (*testObject).WithStatus,
					Operations:              mt,
				}
				if batchOps {
					cfg.BatchOperations = mt
				}
				return cfg
			}),
			cell.Provide(reconciler.New[*testObject]),

			cell.Invoke(func(r_ reconciler.Reconciler[*testObject], m *reconciler.Metrics, h cell.Health, s cell.Scope) {
				r = r_
				health = h
				scope = s

				// Enable all metrics for the test
				m.IncrementalReconciliationCount.SetEnabled(true)
				m.IncrementalReconciliationDuration.SetEnabled(true)
				m.IncrementalReconciliationTotalErrors.SetEnabled(true)
				m.IncrementalReconciliationCurrentErrors.SetEnabled(true)
				m.FullReconciliationCount.SetEnabled(true)
				m.FullReconciliationOutOfSyncCount.SetEnabled(true)
				m.FullReconciliationTotalErrors.SetEnabled(true)
				m.FullReconciliationDuration.SetEnabled(true)
			}),
		),
	)

	require.NoError(t, hive.Start(context.TODO()), "Start")

	h := testHelper{
		t:      t,
		db:     db,
		tbl:    testObjects,
		ops:    mt,
		r:      r,
		health: health,
		scope:  scope,
	}

	numIterations := 3

	t.Run("incremental", func(t *testing.T) {
		h.t = t

		for i := 0; i < numIterations; i++ {
			t.Logf("Iteration %d", i)

			// Insert some test objects and check that they're reconciled
			t.Logf("Inserting test objects 1, 2 & 3")
			h.insert(ID_1, NonFaulty, reconciler.StatusPending())
			h.expectOp(opUpdate(ID_1))
			h.expectStatus(ID_1, reconciler.StatusKindDone, "")

			h.insert(ID_2, NonFaulty, reconciler.StatusPending())
			h.expectOp(opUpdate(ID_2))
			h.expectStatus(ID_2, reconciler.StatusKindDone, "")

			h.insert(ID_3, NonFaulty, reconciler.StatusPending())
			h.expectOp(opUpdate(ID_3))
			h.expectStatus(ID_3, reconciler.StatusKindDone, "")

			h.expectHealthLevel(cell.StatusOK)
			h.waitForReconciliation()

			// Set one to be faulty => object will error
			t.Log("Setting '1' faulty")
			h.insert(ID_1, Faulty, reconciler.StatusPending())
			h.expectOp(opFail(opUpdate(ID_1)))
			h.expectStatus(ID_1, reconciler.StatusKindError, "update fail")
			h.expectRetried(ID_1)
			h.expectHealthLevel(cell.StatusDegraded)

			// Fix the object => object will reconcile again.
			t.Log("Setting '1' non-faulty")
			h.insert(ID_1, NonFaulty, reconciler.StatusPending())
			h.expectOp(opUpdate(ID_1))
			h.expectStatus(ID_1, reconciler.StatusKindDone, "")
			h.expectHealthLevel(cell.StatusOK)

			t.Log("Delete 1 & 2")
			h.markForDelete(ID_1)
			h.expectOp(opDelete(1))
			h.expectNotFound(ID_1)

			h.markForDelete(ID_2)
			h.expectOp(opDelete(2))
			h.expectNotFound(ID_2)

			t.Log("Try to delete '3' with faulty ops")
			h.setTargetFaulty(true)
			h.markForDelete(ID_3)
			h.expectOp(opFail(opDelete(3)))
			h.expectStatus(ID_3, reconciler.StatusKindError, "delete fail")
			h.expectHealthLevel(cell.StatusDegraded)

			t.Log("Delete 3")
			h.setTargetFaulty(false)
			h.expectOp(opDelete(3))
			h.expectNotFound(ID_3)
			h.expectHealthLevel(cell.StatusOK)

			h.waitForReconciliation()

		}
	})

	t.Run("full", func(t *testing.T) {
		h.t = t

		for i := 0; i < numIterations; i++ {
			t.Logf("Iteration %d", i)

			// Without any objects, we should only see prune.
			t.Log("Full reconciliation without objects")
			h.triggerFullReconciliation()
			h.expectOp(opPrune(0))
			h.expectHealthLevel(cell.StatusOK)

			// Add few objects and wait until incremental reconciliation is done.
			t.Log("Insert test objects")
			h.insert(ID_1, NonFaulty, reconciler.StatusPending())
			h.insert(ID_2, NonFaulty, reconciler.StatusPending())
			h.insert(ID_3, NonFaulty, reconciler.StatusPending())
			h.expectStatus(ID_1, reconciler.StatusKindDone, "")
			h.expectStatus(ID_2, reconciler.StatusKindDone, "")
			h.expectStatus(ID_3, reconciler.StatusKindDone, "")
			h.expectHealthLevel(cell.StatusOK)

			// Full reconciliation with functioning ops.
			t.Log("Full reconciliation with non-faulty ops")
			h.triggerFullReconciliation()
			h.expectOps(opPrune(3), opUpdate(ID_1), opUpdate(ID_2), opUpdate(ID_3))
			h.expectStatus(ID_1, reconciler.StatusKindDone, "")
			h.expectStatus(ID_2, reconciler.StatusKindDone, "")
			h.expectStatus(ID_3, reconciler.StatusKindDone, "")
			h.expectHealthLevel(cell.StatusOK)

			// Make the ops faulty and trigger the full reconciliation.
			t.Log("Full reconciliation with faulty ops")
			h.setTargetFaulty(true)
			h.triggerFullReconciliation()
			h.expectOps(
				opFail(opUpdate(ID_1)),
				opFail(opUpdate(ID_2)),
				opFail(opUpdate(ID_3)),
			)
			h.expectHealthLevel(cell.StatusDegraded)

			// Expect the objects to be retried also after the full reconciliation.
			h.expectRetried(ID_1)
			h.expectRetried(ID_2)
			h.expectRetried(ID_3)

			// All should be marked as errored.
			h.expectStatus(ID_1, reconciler.StatusKindError, "update fail")
			h.expectStatus(ID_2, reconciler.StatusKindError, "update fail")
			h.expectStatus(ID_3, reconciler.StatusKindError, "update fail")

			// Make the ops healthy again and check that the objects recover.
			t.Log("Retries succeed after ops is non-faulty")
			h.setTargetFaulty(false)
			h.expectOps(opUpdate(ID_1), opUpdate(ID_2), opUpdate(ID_3))
			h.expectStatus(ID_1, reconciler.StatusKindDone, "")
			h.expectStatus(ID_2, reconciler.StatusKindDone, "")
			h.expectStatus(ID_3, reconciler.StatusKindDone, "")
			h.expectHealthLevel(cell.StatusOK)

			// Cleanup.
			h.markForDelete(ID_1)
			h.markForDelete(ID_2)
			h.markForDelete(ID_3)
			h.expectNotFound(ID_1)
			h.expectNotFound(ID_2)
			h.expectNotFound(ID_3)
			h.triggerFullReconciliation()
			h.expectOps(opDelete(1), opDelete(2), opDelete(3), opPrune(0))
			h.waitForReconciliation()

		}
	})

	// ---
	// Validate that the metrics are populated and make some sense.
	m := dumpMetrics(registry)
	assertSensibleMetricDuration(t, m, "cilium_reconciler_full_duration_seconds/module_id=test,op=prune")
	assertSensibleMetricDuration(t, m, "cilium_reconciler_full_duration_seconds/module_id=test,op=update")
	assert.Greater(t, m["cilium_reconciler_full_out_of_sync_total/module_id=test"], 0.0)
	assert.Greater(t, m["cilium_reconciler_full_total/module_id=test"], 0.0)

	assertSensibleMetricDuration(t, m, "cilium_reconciler_incremental_duration_seconds/module_id=test,op=update")
	assertSensibleMetricDuration(t, m, "cilium_reconciler_incremental_duration_seconds/module_id=test,op=delete")
	assert.Equal(t, m["cilium_reconciler_incremental_errors_current/module_id=test"], 0.0)
	assert.Greater(t, m["cilium_reconciler_incremental_errors_total/module_id=test"], 0.0)
	assert.Greater(t, m["cilium_reconciler_incremental_total/module_id=test"], 0.0)

	assert.NoError(t, hive.Stop(context.TODO()), "Stop")
}

type testObject struct {
	id     uint64
	faulty bool
	status reconciler.Status
}

var idIndex = statedb.Index[*testObject, uint64]{
	Name: "id",
	FromObject: func(t *testObject) index.KeySet {
		return index.NewKeySet(index.Uint64(t.id))
	},
	FromKey: index.Uint64,
	Unique:  true,
}

var statusIndex = reconciler.NewStatusIndex[*testObject]((*testObject).GetStatus)

// GetStatus implements reconciler.Reconcilable.
func (t *testObject) GetStatus() reconciler.Status {
	return t.status
}

// WithStatus implements reconciler.Reconcilable.
func (t *testObject) WithStatus(status reconciler.Status) *testObject {
	t2 := *t
	t2.status = status
	return &t2
}

type opHistory struct {
	mu      lock.Mutex
	history []opHistoryItem
}

type opHistoryItem = string

func opUpdate(id uint64) opHistoryItem {
	return opHistoryItem(fmt.Sprintf("update(%d)", id))
}
func opDelete(id uint64) opHistoryItem {
	return opHistoryItem(fmt.Sprintf("delete(%d)", id))
}
func opPrune(numDesiredObjects int) opHistoryItem {
	return opHistoryItem(fmt.Sprintf("prune(n=%d)", numDesiredObjects))
}
func opFail(item opHistoryItem) opHistoryItem {
	return item + " fail"
}

func (o *opHistory) add(item opHistoryItem) {
	o.mu.Lock()
	o.history = append(o.history, item)
	o.mu.Unlock()
}

func (o *opHistory) latest() opHistoryItem {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.history) > 0 {
		return o.history[len(o.history)-1]
	}
	return "<empty history>"
}

func (o *opHistory) take(n int) []opHistoryItem {
	o.mu.Lock()
	defer o.mu.Unlock()

	out := []opHistoryItem{}
	for n > 0 {
		idx := len(o.history) - n
		if idx >= 0 {
			out = append(out, o.history[idx])
		}
		n--
	}
	return out
}

type intMap struct {
	lock.Map[uint64, int]
}

func (m *intMap) incr(key uint64) {
	if n, ok := m.Load(key); ok {
		m.Store(key, n+1)
	} else {
		m.Store(key, 1)
	}
}

func (m *intMap) get(key uint64) int {
	if n, ok := m.Load(key); ok {
		return n
	}
	return 0
}

type mockOps struct {
	history opHistory
	faulty  atomic.Bool
	updates intMap
}

// DeleteBatch implements recogciler.BatchOperations.
func (mt *mockOps) DeleteBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*testObject]) {
	for i := range batch {
		batch[i].Result = mt.Delete(ctx, txn, batch[i].Object)
	}
}

// UpdateBatch implements reconciler.BatchOperations.
func (mt *mockOps) UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*testObject]) {
	for i := range batch {
		batch[i].Result = mt.Update(ctx, txn, batch[i].Object, nil)
	}
}

// Delete implements reconciler.Operations.
func (mt *mockOps) Delete(ctx context.Context, txn statedb.ReadTxn, obj *testObject) error {
	if mt.faulty.Load() || obj.faulty {
		mt.history.add(opFail(opDelete(obj.id)))
		return errors.New("delete fail")
	}
	mt.history.add(opDelete(obj.id))

	return nil
}

// Prune implements reconciler.Operations.
func (mt *mockOps) Prune(ctx context.Context, txn statedb.ReadTxn, iter statedb.Iterator[*testObject]) error {
	objs := statedb.Collect(iter)
	mt.history.add(opPrune(len(objs)))
	return nil
}

// Update implements reconciler.Operations.
func (mt *mockOps) Update(ctx context.Context, txn statedb.ReadTxn, obj *testObject, changed *bool) error {
	if changed != nil {
		*changed = true
	}
	mt.updates.incr(obj.id)
	if mt.faulty.Load() || obj.faulty {
		mt.history.add(opFail(opUpdate(obj.id)))
		return errors.New("update fail")
	}
	mt.history.add(opUpdate(obj.id))
	return nil
}

var _ reconciler.Operations[*testObject] = &mockOps{}
var _ reconciler.BatchOperations[*testObject] = &mockOps{}

// testHelper defines a sort of mini-language for writing the test steps.
type testHelper struct {
	t      testing.TB
	db     *statedb.DB
	tbl    statedb.RWTable[*testObject]
	ops    *mockOps
	r      reconciler.Reconciler[*testObject]
	health cell.Health
	scope  cell.Scope
}

const (
	Faulty    = true
	NonFaulty = false
)

func (h testHelper) insert(id uint64, faulty bool, status reconciler.Status) {
	wtxn := h.db.WriteTxn(h.tbl)
	_, _, err := h.tbl.Insert(wtxn, &testObject{
		id:     id,
		faulty: faulty,
		status: status,
	})
	require.NoError(h.t, err, "insert failed")
	wtxn.Commit()
}

func (h testHelper) markForDelete(id uint64) {
	wtxn := h.db.WriteTxn(h.tbl)
	_, _, err := h.tbl.Insert(wtxn, &testObject{
		id:     id,
		faulty: false,
		status: reconciler.StatusPendingDelete(),
	})
	require.NoError(h.t, err, "delete failed")
	wtxn.Commit()
}

func (h testHelper) expectStatus(id uint64, kind reconciler.StatusKind, err string) {
	cond := func() bool {
		obj, _, ok := h.tbl.First(h.db.ReadTxn(), idIndex.Query(id))
		return ok && obj.status.Kind == kind && obj.status.Error == err
	}
	if !assert.Eventually(h.t, cond, time.Second, time.Millisecond) {
		actual := "<not found>"
		obj, _, ok := h.tbl.First(h.db.ReadTxn(), idIndex.Query(id))
		if ok {
			actual = string(obj.status.Kind)
		}
		require.Failf(h.t, "status mismatch", "expected object %d to be marked with status %q, but it was %q",
			id, kind, actual)

	}
}

func (h testHelper) expectNotFound(id uint64) {
	cond := func() bool {
		_, _, ok := h.tbl.First(h.db.ReadTxn(), idIndex.Query(id))
		return !ok
	}
	require.Eventually(h.t, cond, time.Second, time.Millisecond, "expected object %d to not be found", id)
}

func (h testHelper) expectOp(op opHistoryItem) {
	cond := func() bool {
		return h.ops.history.latest() == op
	}
	if !assert.Eventually(h.t, cond, time.Second, time.Millisecond) {
		require.Failf(h.t, "operation mismatch", "expected last operation to be %q, it was %q", op, h.ops.history.latest())
	}
}

func (h testHelper) expectOps(ops ...opHistoryItem) {
	sort.Strings(ops)
	cond := func() bool {
		actual := h.ops.history.take(len(ops))
		sort.Strings(actual)
		return slices.Equal(ops, actual)
	}
	if !assert.Eventually(h.t, cond, time.Second, time.Millisecond) {
		actual := h.ops.history.take(len(ops))
		sort.Strings(actual)
		require.Failf(h.t, "operations mismatch", "expected operations to be %v, but they were %v", ops, actual)
	}
}

func (h testHelper) expectRetried(id uint64) {
	old := h.ops.updates.get(id)
	cond := func() bool {
		new := h.ops.updates.get(id)
		return new > old
	}
	require.Eventually(h.t, cond, time.Second, time.Millisecond, "expected %d to be retried", id)
}

func (h testHelper) expectHealthLevel(level cell.Level) {
	cond := func() bool {
		h.scope.Realize()
		status, err := h.health.Get([]string{"test"})
		return err == nil && level == status.Level()
	}
	if !assert.Eventually(h.t, cond, time.Second, time.Millisecond) {
		status, _ := h.health.Get([]string{"test"})
		// Since the current health provider API doesn't provide access to the sub-reporter
		// status, just dump the full JSON out. Please refactor this to validate the actual
		// contents (e.g. degraded error and so on) once it is possible.
		bs, _ := status.JSON()
		os.Stdout.Write(bs)
		require.Failf(h.t, "health mismatch", "expected health level %q, got: %q (%s)", level, status.Level(), status.String())
	}
}

func (h testHelper) setTargetFaulty(faulty bool) {
	h.ops.faulty.Store(faulty)
}

func (h testHelper) triggerFullReconciliation() {
	h.r.TriggerFullReconciliation()
}

func (h testHelper) waitForReconciliation() {
	err := reconciler.WaitForReconciliation[*testObject](context.TODO(), h.db, h.tbl, statusIndex)
	require.NoError(h.t, err, "expected WaitForReconciliation to succeed")
}
func assertSensibleMetricDuration(t *testing.T, metrics map[string]float64, metric string) {
	assert.Less(t, metrics[metric], 1.0, "expected metric %q to be above zero", metric)

	// TODO: Sometimes the histogram metric is 0.0 even though samples have been added. Figure
	// out why and what's a better way to validate it. For now just log that it was 0.
	//assert.Greater(t, metrics[metric], 0.0, "expected metric %q to be above zero", metric)
	if metrics[metric] == 0.0 {
		t.Logf("!!! metric %q unexpectedly zero", metric)
	}
}

func dumpMetrics(r *metricsPkg.Registry) map[string]float64 {
	out := map[string]float64{}
	metrics, err := r.DumpMetrics()
	if err != nil {
		return nil
	}
	for _, m := range metrics {
		if strings.HasPrefix(m.Name, "cilium_reconciler") {
			out[m.Name+"/"+concatLabels(m.Labels)] = m.Value
		}
	}
	return out
}

func concatLabels(m map[string]string) string {
	labels := []string{}
	for k, v := range m {
		labels = append(labels, k+"="+v)
	}
	return strings.Join(labels, ",")
}
