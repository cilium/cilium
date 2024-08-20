// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"encoding"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

type TestObject struct {
	Key    TestKey
	Value  TestValue
	Status reconciler.Status
}

func (o *TestObject) BinaryKey() encoding.BinaryMarshaler {
	return StructBinaryMarshaler{&o.Key}
}

func (o *TestObject) BinaryValue() encoding.BinaryMarshaler {
	return StructBinaryMarshaler{&o.Value}
}

type emptyIterator struct{}

func (*emptyIterator) Next() (*TestObject, uint64, bool) {
	return nil, 0, false
}

var _ statedb.Iterator[*TestObject] = &emptyIterator{}

func Test_MapOps(t *testing.T) {
	testutils.PrivilegedTest(t)

	testMap := NewMap("cilium_ops_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC,
	)

	err := testMap.OpenOrCreate()
	require.NoError(t, err, "OpenOrCreate")
	defer testMap.Close()

	ctx := context.TODO()
	ops := NewMapOps[*TestObject](testMap)
	obj := &TestObject{Key: TestKey{1}, Value: TestValue{2}}

	// Test Update() and Delete()
	err = ops.Update(ctx, nil, obj)
	assert.NoError(t, err, "Update")

	err = ops.Update(ctx, nil, obj)
	assert.NoError(t, err, "Update")

	v, err := testMap.Lookup(&TestKey{1})
	assert.NoError(t, err, "Lookup")
	assert.Equal(t, v.(*TestValue).Value, obj.Value.Value)

	err = ops.Delete(ctx, nil, obj)
	assert.NoError(t, err, "Delete")

	_, err = testMap.Lookup(&TestKey{1})
	assert.Error(t, err, "Lookup")

	// Test Prune()
	err = testMap.Update(&TestKey{2}, &TestValue{3})
	assert.NoError(t, err, "Update")

	v, err = testMap.Lookup(&TestKey{2})
	if assert.NoError(t, err, "Lookup") {
		assert.Equal(t, v.(*TestValue).Value, uint32(3))
	}

	// Give Prune() an empty set of objects, which should cause it to
	// remove everything.
	err = ops.Prune(ctx, nil, &emptyIterator{})
	assert.NoError(t, err, "Prune")

	data := map[string][]string{}
	testMap.Dump(data)
	assert.Len(t, data, 0)
}

func Test_MapOpsPrune(t *testing.T) {
	testutils.PrivilegedTest(t)

	// This tests pruning with an LPM trie. This ensures we do not regress, as
	// previously we had issues with Prune concurrently iterating and deleting
	// entries, which caused the iteration to skip entries
	testMap := NewMap(
		"cilium_ops_prune_test",
		ebpf.LPMTrie,
		&TestLPMKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC,
	)
	err := testMap.OpenOrCreate()
	require.NoError(t, err, "OpenOrCreate")
	defer testMap.Close()

	ctx := context.TODO()
	ops := NewMapOps[*TestObject](testMap)

	// Fill map with similarly prefixed entries
	err = testMap.Update(&TestLPMKey{32, 0xFF00_00FF}, &TestValue{0})
	assert.NoError(t, err, "Update 0")
	err = testMap.Update(&TestLPMKey{32, 0xFF01_01FF}, &TestValue{1})
	assert.NoError(t, err, "Update 1")
	err = testMap.Update(&TestLPMKey{32, 0xFF02_02FF}, &TestValue{2})
	assert.NoError(t, err, "Update 2")
	err = testMap.Update(&TestLPMKey{32, 0xFF03_03FF}, &TestValue{3})
	assert.NoError(t, err, "Update 3")

	// Prune should now remove everything
	err = ops.Prune(ctx, nil, &emptyIterator{})
	assert.NoError(t, err, "Prune")

	data := map[string][]string{}
	testMap.Dump(data)
	assert.Len(t, data, 0)
}

// Test_MapOps_ReconcilerExample serves as a testable example for the map ops.
// This is not an "Example*" function as it can only run privileged.
func Test_MapOps_ReconcilerExample(t *testing.T) {
	testutils.PrivilegedTest(t)

	exampleMap := NewMap("example",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC,
	)
	err := exampleMap.OpenOrCreate()
	require.NoError(t, err)
	t.Cleanup(func() { exampleMap.Close() })

	// Create the table containing the desired state of the map.
	keyIndex := statedb.Index[*TestObject, uint32]{
		Name: "example",
		FromObject: func(obj *TestObject) index.KeySet {
			return index.NewKeySet(index.Uint32(obj.Key.Key))
		},
		FromKey: index.Uint32,
		Unique:  true,
	}
	table, err := statedb.NewTable("example", keyIndex)
	require.NoError(t, err, "NewTable")

	// Create the map operations and the reconciler configuration.
	ops := NewMapOps[*TestObject](exampleMap)

	// Silence the hive log output.
	oldLogLevel := logging.DefaultLogger.GetLevel()
	logging.SetLogLevel(logrus.ErrorLevel)
	t.Cleanup(func() {
		logging.SetLogLevel(oldLogLevel)
	})

	// Setup and start a hive to run the reconciler.
	var db *statedb.DB
	h := hive.New(
		cell.Module(
			"example",
			"Example",

			cell.Invoke(
				func(db_ *statedb.DB) error {
					db = db_
					return db.RegisterTable(table)
				},
			),
			cell.Invoke(
				func(params reconciler.Params) error {
					_, err := reconciler.Register[*TestObject](
						params,
						table,
						func(obj *TestObject) *TestObject {
							obj2 := *obj
							return &obj2
						},
						func(obj *TestObject, s reconciler.Status) *TestObject {
							obj.Status = s
							return obj
						},
						func(obj *TestObject) reconciler.Status {
							return obj.Status
						},
						ops,
						nil,
					)
					return err
				}),
		),
	)

	tlog := hivetest.Logger(t)
	err = h.Start(tlog, context.Background())
	require.NoError(t, err, "Start")

	t.Cleanup(func() {
		h.Stop(tlog, context.Background())
	})

	// Insert an object to the desired state and wait for it to reconcile.
	txn := db.WriteTxn(table)
	table.Insert(txn, &TestObject{
		Key:   TestKey{1},
		Value: TestValue{2},

		// Mark the object to be pending for reconciliation. Without this
		// the reconciler would ignore this object.
		Status: reconciler.StatusPending(),
	})
	txn.Commit()

	for {
		obj, _, watch, ok := table.GetWatch(db.ReadTxn(), keyIndex.Query(1))
		if ok {
			if obj.Status.Kind == reconciler.StatusKindDone {
				// The object has been reconciled.
				break
			}
			t.Logf("Object not done yet: %#v", obj)
		}
		// Wait for the object to update
		<-watch
	}

	v, err := exampleMap.Lookup(&TestKey{1})
	require.NoError(t, err, "Lookup")
	require.Equal(t, uint32(2), v.(*TestValue).Value)

	// Mark the object for deletion
	txn = db.WriteTxn(table)
	table.Delete(txn, &TestObject{
		Key:   TestKey{1},
		Value: TestValue{2},
	})
	txn.Commit()

	for {
		obj, _, watch, ok := table.GetWatch(db.ReadTxn(), keyIndex.Query(1))
		if !ok {
			// The object has been successfully deleted.
			break
		}
		t.Logf("Object not deleted yet: %#v", obj)
		// Wait for the object to update
		<-watch
	}

	require.Eventually(
		t,
		func() bool {
			_, err = exampleMap.Lookup(&TestKey{1})
			return errors.Is(err, ebpf.ErrKeyNotExist)
		},
		time.Second,
		100*time.Millisecond,
		"Expected key to eventually be removed")

}
