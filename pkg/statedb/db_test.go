// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	memdb "github.com/hashicorp/go-memdb"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type Foo struct {
	UUID UUID

	Num uint64
}

func (f *Foo) DeepCopy() *Foo {
	return &Foo{
		UUID: f.UUID,
		Num:  f.Num,
	}
}

var fooTableSchema = &memdb.TableSchema{
	Name: "foos",
	Indexes: map[string]*memdb.IndexSchema{
		"id": UUIDIndexSchema,
	},
}

func TestDB(t *testing.T) {
	hive := hive.New(
		cell.Provide(func() *testing.T { return t }),

		Cell,
		NewTableCell[*Foo](fooTableSchema),

		cell.Invoke(runTest),
	)
	hive.Start(context.TODO())
	hive.Stop(context.TODO())
}

type testParams struct {
	cell.In

	DB   DB
	Foos Table[*Foo]
}

func runTest(t *testing.T, p testParams) {
	db := p.DB
	fooId1, fooId2 := NewUUID(), NewUUID()

	// Helper function to assert that the two "foo" objects exist.
	assertGet := func(tx ReadTransaction) {
		foos := p.Foos.Reader(tx)

		it, err := foos.Get(ByID(fooId1))
		if assert.NoError(t, err) {
			obj, ok := it.Next()
			if assert.True(t, ok, "Iterator should return object") {
				assert.Equal(t, uint64(1), obj.Num)
			}
			_, ok = it.Next()
			assert.False(t, ok, "Iterator should have returned only one object")
		}

		it, err = foos.Get(ByID(fooId2))
		if assert.NoError(t, err) {
			obj, ok := it.Next()
			if assert.True(t, ok, "Iterator should return object") {
				assert.Equal(t, uint64(2), obj.Num)
			}
			_, ok = it.Next()
			assert.False(t, ok, "Iterator should have returned only one object")
		}

		it, err = foos.Get(ByID(NewUUID()))
		if assert.NoError(t, err) { // No error since our query was wellformed
			_, ok := it.Next()
			assert.False(t, ok, "Query with unknown ID should have returned no results")
		}
	}

	// Create the two foos
	{
		tx := db.WriteTxn()
		foos := p.Foos.Writer(tx)
		err := foos.Insert(&Foo{UUID: fooId1, Num: 1})
		assert.NoError(t, err)

		err = foos.Insert(&Foo{UUID: fooId2, Num: 2})
		assert.NoError(t, err)

		assertGet(tx)
		tx.Commit()
	}

	// Check that it's been committed.
	assertGet(db.ReadTxn())

	// Check that we can iterate over all nodes.
	rtx := db.ReadTxn()
	it, err := p.Foos.Reader(rtx).Get(All)
	if assert.NoError(t, err) {
		n := 0
		ProcessEach(it, func(f *Foo) error {
			n++
			return nil
		})
		assert.EqualValues(t, 2, n)
	}

	// Check that we're notified when the results change
	ch := it.Invalidated()
	select {
	case <-ch:
		t.Errorf("expected Invalidated() channel to block!")
	default:
	}

	tx2 := db.WriteTxn()
	err = p.Foos.Writer(tx2).Insert(&Foo{UUID: NewUUID(), Num: 3})
	assert.NoError(t, err)
	tx2.Commit()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Errorf("expected Invalidated() channel to be closed!")
	}

	// Check that modifications to existing objects also result in notification.
	it, err = p.Foos.Reader(db.ReadTxn()).Get(All)
	assert.NoError(t, err)
	ch = it.Invalidated()
	select {
	case <-ch:
		t.Errorf("expected Invalidated() channel to block!")
	default:
	}

	tx3 := db.WriteTxn()
	foo2, err := p.Foos.Reader(tx3).First(ByUUID(fooId2))
	assert.NoError(t, err)
	assert.NotNil(t, foo2)
	foo2 = foo2.DeepCopy()
	foo2.Num = 222
	err = p.Foos.Writer(tx3).Insert(foo2)
	assert.NoError(t, err)
	tx3.Commit()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Errorf("expected Invalidated() channel to be closed!")
	}

	it, err = p.Foos.Reader(db.ReadTxn()).Get(All)
	assert.NoError(t, err)
	assert.Equal(t, Length[*Foo](it), 3)

	// Aborting doesn't change anything.
	tx4 := db.WriteTxn()
	err = p.Foos.Writer(tx4).Insert(&Foo{UUID: NewUUID(), Num: 3})
	assert.NoError(t, err)
	tx4.Abort()

	it, err = p.Foos.Reader(db.ReadTxn()).Get(All)
	assert.NoError(t, err)
	assert.Equal(t, Length[*Foo](it), 3)

	// Validate that WriteJSON does something useful.
	buf := new(bytes.Buffer)
	err = db.WriteJSON(buf)
	assert.NoError(t, err, "WriteJSON should succeed")
	out := buf.Bytes()

	var result map[string][]Foo
	err = json.Unmarshal(out, &result)
	assert.NoError(t, err, "WriteJSON output should be valid JSON")
	foos, ok := result[fooTableSchema.Name]
	assert.True(t, ok, "There should be a 'foos' table")
	assert.Len(t, foos, 3)
	assert.True(t, foos[0].Num > 0)
	assert.True(t, len(foos[0].UUID) > 0)
}

// Benchmark how many insertions per second can be performed on a table with UUID primary
// key. On a 3.4Ghz i5 laptop I'm seeing 2719 ns/op, e.g. ~350k per second.
func BenchmarkDB_Insert_UUID(b *testing.B) {
	var (
		db   DB
		foos Table[*Foo]
	)
	hive := hive.New(
		Cell,
		NewTableCell[*Foo](fooTableSchema),
		cell.Invoke(func(db_ DB, foos_ Table[*Foo]) { db = db_; foos = foos_ }),
	)
	hive.Start(context.TODO())
	defer hive.Stop(context.TODO())

	b.ResetTimer()
	tx := db.WriteTxn()
	w := foos.Writer(tx)
	for i := uint64(0); i < uint64(b.N); i++ {
		uuid := fmt.Sprintf("00000000-0000-0000-0000-%012x", i)
		err := w.Insert(&Foo{UUID: uuid, Num: i})
		if err != nil {
			b.Fatalf("Insert error: %s", err)
		}
	}
	tx.Commit()
}

// Benchmark how many one insertion write transactions per second can be performed.
// On a 3.4Ghz i5 laptop I'm seeing 9256 ns/op, e.g. ~100k per second.
func BenchmarkDB_WriteTxn(b *testing.B) {
	var (
		db   DB
		foos Table[*Foo]
	)
	hive := hive.New(
		Cell,
		NewTableCell[*Foo](fooTableSchema),
		cell.Invoke(func(db_ DB, foos_ Table[*Foo]) { db = db_; foos = foos_ }),
	)
	hive.Start(context.TODO())
	defer hive.Stop(context.TODO())

	b.ResetTimer()
	for i := uint64(0); i < uint64(b.N); i++ {
		uuid := fmt.Sprintf("00000000-0000-0000-0000-%012x", i)
		tx := db.WriteTxn()
		w := foos.Writer(tx)
		err := w.Insert(&Foo{UUID: uuid, Num: i})
		if err != nil {
			b.Fatalf("Insert error: %s", err)
		}
		tx.Commit()
	}
}
