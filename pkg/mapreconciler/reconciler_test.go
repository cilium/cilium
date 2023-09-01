// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mapreconciler

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

type fixture struct {
	reconciler *mapReconciler[TestEntry, TestKey, TestValue]
	stateDB    *statedb.DB
	table      statedb.Table[TestEntry]
	fm         *FakeMap
}

func newFixture() *fixture {
	var (
		db    *statedb.DB
		jg    job.Group
		table statedb.Table[TestEntry]
	)

	pk := PrimaryKeyIndex[TestEntry, TestKey, TestValue]()

	hive.New(
		statedb.Cell,
		job.Cell,
		statedb.NewTableCell("test-table", pk),
		cell.Invoke(func(
			d *statedb.DB,
			jr job.Registry,
			tbl statedb.Table[TestEntry],
		) {
			db = d
			jg = jr.NewGroup()
			table = tbl
		}),
	).Populate()

	fm := &FakeMap{
		name:    "test-map",
		enabled: true,
		inner:   make(map[TestKey]TestValue),
	}

	return &fixture{
		reconciler: newMapReconciler(fm, db, table, pk, jg, defaultOptions[TestEntry]()),
		stateDB:    db,
		table:      table,
		fm:         fm,
	}
}

func TestFullHappy(t *testing.T) {
	fix := newFixture()

	// Set a value in the map, which will not be in the desired state.
	fix.fm.Put(TestKey{index: 123}, TestValue{someSetting: 123})

	txn := fix.stateDB.WriteTxn(fix.table)
	_, _, err := fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	txn.Commit()

	_ = fix.reconciler.fullReconciliation(context.Background())

	// The value in the map should have been deleted, and replaced by the value in the table
	v, err := fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 123})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 0}, v)
}

func TestPartialHappy(t *testing.T) {
	fix := newFixture()

	// Set a value in the map, which will not be in the desired state.
	fix.fm.Put(TestKey{index: 123}, TestValue{someSetting: 123})

	txn := fix.stateDB.WriteTxn(fix.table)
	rev := fix.table.Revision(txn)
	_, _, err := fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	txn.Commit()

	dt, err := fix.reconciler.newDeleteTracker()
	assert.NoError(t, err)
	rev, _ = fix.reconciler.partialReconciliation(context.Background(), dt, rev)

	// The value in the map will not have changed, and the desired entry added to the map.
	v, err := fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 123})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 123}, v)

	// Deleting the entry from the table should cause the value to be deleted from the map.

	txn = fix.stateDB.WriteTxn(fix.table)
	_, _, err = fix.table.Delete(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	txn.Commit()

	_, _ = fix.reconciler.partialReconciliation(context.Background(), dt, rev)

	// The value just deleted from the desired state should now also be deleted. The rogue value is unaffected.
	v, err = fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 0}, v)

	v, err = fix.fm.Lookup(TestKey{index: 123})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 123}, v)
}

func TestPutErrorInFullReconciliation(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.table)
	_, _, err := fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	_, _, err = fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 2},
		val: TestValue{someSetting: 2},
	})
	assert.NoError(t, err)
	_, _, err = fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 3},
		val: TestValue{someSetting: 3},
	})
	assert.NoError(t, err)
	txn.Commit()

	// Only throw an error for the second entry
	fix.fm.putError = func(k TestKey) error {
		if k.index == 2 {
			return errors.New("some error")
		}

		return nil
	}

	_ = fix.reconciler.fullReconciliation(context.Background())

	// Expect the first and last entry to be in the map

	v, err := fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 2})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 0}, v)

	v, err = fix.fm.Lookup(TestKey{index: 3})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 3}, v)

	// Don't throw errors anymore
	fix.fm.putError = nil

	ctx, cancel := context.WithCancel(context.Background())
	go fix.reconciler.Retirer(ctx)

	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			t.Log("retrier did not finish in time")
			t.Fail()
		default:
			time.Sleep(10 * time.Millisecond)
		}

		v, err = fix.fm.Lookup(TestKey{index: 2})
		assert.NoError(t, err)
		if v.someSetting != 0 {
			break
		}
	}
	cancel()
}

func TestPutErrorInPartialReconciliation(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.table)
	rev := fix.table.Revision(txn)
	_, _, err := fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	_, _, err = fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 2},
		val: TestValue{someSetting: 2},
	})
	assert.NoError(t, err)
	_, _, err = fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 3},
		val: TestValue{someSetting: 3},
	})
	assert.NoError(t, err)
	txn.Commit()

	// Only throw an error for the second entry
	fix.fm.putError = func(k TestKey) error {
		if k.index == 2 {
			return errors.New("some error")
		}

		return nil
	}

	dt, err := fix.reconciler.newDeleteTracker()
	assert.NoError(t, err)
	_, _ = fix.reconciler.partialReconciliation(context.Background(), dt, rev)

	// Expect the first and last entry to be in the map

	v, err := fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 2})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 0}, v)

	v, err = fix.fm.Lookup(TestKey{index: 3})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 3}, v)

	// Don't throw errors anymore
	fix.fm.putError = nil

	ctx, cancel := context.WithCancel(context.Background())
	go fix.reconciler.Retirer(ctx)

	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			t.Log("retrier did not finish in time")
			t.Fail()
		default:
			time.Sleep(10 * time.Millisecond)
		}

		v, err = fix.fm.Lookup(TestKey{index: 2})
		assert.NoError(t, err)
		if v.someSetting != 0 {
			break
		}
	}
	cancel()
}

func TestDeleteErrorInFullReconciliation(t *testing.T) {
	fix := newFixture()

	fix.fm.Put(TestKey{index: 123}, TestValue{someSetting: 123})

	txn := fix.stateDB.WriteTxn(fix.table)
	_, _, err := fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	txn.Commit()

	// Only throw an error for the 123 entry
	fix.fm.deleteError = func(k TestKey) error {
		if k.index == 123 {
			return errors.New("some error")
		}

		return nil
	}

	_ = fix.reconciler.fullReconciliation(context.Background())

	// Expect the first and last entry to be in the map

	v, err := fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 123})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 123}, v)

	// Don't throw errors anymore
	fix.fm.deleteError = nil

	ctx, cancel := context.WithCancel(context.Background())
	go fix.reconciler.Retirer(ctx)

	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			t.Log("retrier did not finish in time")
			t.Fail()
		default:
			time.Sleep(10 * time.Millisecond)
		}

		v, err = fix.fm.Lookup(TestKey{index: 123})
		assert.NoError(t, err)
		if v.someSetting == 0 {
			break
		}
	}
	cancel()
}

func TestDeleteErrorInPartialReconciliation(t *testing.T) {
	fix := newFixture()

	txn := fix.stateDB.WriteTxn(fix.table)
	rev := fix.table.Revision(txn)
	_, _, err := fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 1},
		val: TestValue{someSetting: 1},
	})
	assert.NoError(t, err)
	_, _, err = fix.table.Insert(txn, TestEntry{
		key: TestKey{index: 123},
		val: TestValue{someSetting: 123},
	})
	assert.NoError(t, err)
	txn.Commit()

	dt, err := fix.reconciler.newDeleteTracker()
	assert.NoError(t, err)
	rev, _ = fix.reconciler.partialReconciliation(context.Background(), dt, rev)

	v, err := fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 123})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 123}, v)

	txn = fix.stateDB.WriteTxn(fix.table)
	_, _, err = fix.table.Delete(txn, TestEntry{
		key: TestKey{index: 123},
		val: TestValue{someSetting: 123},
	})
	assert.NoError(t, err)
	txn.Commit()

	// Only throw an error for the second entry
	fix.fm.deleteError = func(k TestKey) error {
		if k.index == 123 {
			return errors.New("some error")
		}

		return nil
	}

	_, _ = fix.reconciler.partialReconciliation(context.Background(), dt, rev)

	// Expect the first and last entry to be in the map

	v, err = fix.fm.Lookup(TestKey{index: 1})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 1}, v)

	v, err = fix.fm.Lookup(TestKey{index: 123})
	assert.NoError(t, err)
	assert.Equal(t, TestValue{someSetting: 123}, v)

	// Don't throw errors anymore
	fix.fm.deleteError = nil

	ctx, cancel := context.WithCancel(context.Background())
	go fix.reconciler.Retirer(ctx)

	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			t.Log("retrier did not finish in time")
			t.Fail()
		default:
			time.Sleep(10 * time.Millisecond)
		}

		v, err = fix.fm.Lookup(TestKey{index: 123})
		assert.NoError(t, err)
		if v.someSetting == 0 {
			break
		}
	}
	cancel()
}

// This tests affirms that the reconciler behaves as expected during it lifecycle, shutting down cleanly
func TestReconcilerLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	startCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pk := PrimaryKeyIndex[TestEntry, TestKey, TestValue]()

	h := hive.New(
		statedb.Cell,
		statedb.NewTableCell("test-table", pk),
		cell.Provide(func() statedb.Index[TestEntry, TestKey] {
			return pk
		}),
		job.Cell,
		NewReconciler[TestEntry](),
		cell.Provide(func() Map[TestKey, TestValue] {
			return &FakeMap{inner: make(map[TestKey]TestValue)}
		}),
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableL2Announcements: true,
			}
		}),
	)
	err := h.Start(startCtx)
	if assert.NoError(t, err) {
		// Give everything some time to start
		time.Sleep(3 * time.Second)

		stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		err = h.Stop(stopCtx)
		assert.NoError(t, err)
	}
}

type TestEntry struct {
	key TestKey
	val TestValue
}

func (e TestEntry) Key() TestKey {
	return e.key
}

func (e TestEntry) Value() TestValue {
	return e.val
}

type TestKey struct {
	index uint64
}

func (k TestKey) Marshal() []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], k.index)
	return buf[:]
}

type TestValue struct {
	someSetting uint32
}

type FakeMap struct {
	name    string
	enabled bool
	inner   map[TestKey]TestValue

	lookupError func(k TestKey) error
	putError    func(k TestKey) error
	deleteError func(k TestKey) error
}

func (fm *FakeMap) Name() string {
	return fm.name
}
func (fm *FakeMap) Enabled() bool {
	return fm.enabled
}
func (fm *FakeMap) Lookup(key TestKey) (TestValue, error) {
	if fm.lookupError != nil {
		if err := fm.lookupError(key); err != nil {
			return TestValue{}, err
		}
	}

	return fm.inner[key], nil
}
func (fm *FakeMap) Put(key TestKey, value TestValue) error {
	if fm.putError != nil {
		if err := fm.putError(key); err != nil {
			return err
		}
	}

	fm.inner[key] = value
	return nil
}

func (fm *FakeMap) Delete(key TestKey) error {
	if fm.deleteError != nil {
		if err := fm.deleteError(key); err != nil {
			return err
		}
	}

	delete(fm.inner, key)
	return nil
}

func (fm *FakeMap) Iterate() Iterator[TestKey, TestValue] {
	i := TestIterator{}
	for k, v := range fm.inner {
		i.pairs = append(i.pairs, testPair{key: k, value: v})
	}
	return &i
}

type testPair struct {
	key   TestKey
	value TestValue
}

type TestIterator struct {
	i     int
	pairs []testPair
}

func (ti *TestIterator) Next(k *TestKey, v *TestValue) bool {
	if ti.i >= len(ti.pairs) {
		return false
	}

	*k, *v = ti.pairs[ti.i].key, ti.pairs[ti.i].value
	ti.i++
	return true
}

func (ti *TestIterator) Err() error {
	return nil
}
