// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/hive"
)

const (
	key   = "dummy_key"
	value = "dummy_value"
)

var timeout = 2 * time.Second

func TestConfigTableGetter_List(t *testing.T) {
	db, ct, ctg := getterFixture(t)
	initialEntries := []ConfigEntry{NewConfigEntry("a", "aa"), NewConfigEntry("b", "bb"), NewConfigEntry("c", "cc")}
	for _, entry := range initialEntries {
		upsertDummyEntry(db, ct, entry.Key, entry.Value)
	}

	entries := ctg.List()

	if !reflect.DeepEqual(entries, initialEntries) {
		t.Errorf("List() do not match: expected %v, got %v", initialEntries, entries)
	}
}

func TestConfigTableGetter_Watch(t *testing.T) {
	db, ct, ctg := getterFixture(t)
	done := make(chan bool)
	newValue := "newValue"

	upsertDummyEntry(db, ct, key, value)

	e, w := ctg.Watch(key)

	if e.Key != key || e.Value != value {
		t.Errorf("Entry mismatch for key %v: expected (key=%v, value=%v), but got (key=%v, value=%v)", key, key, value, e.Key, e.Value)
	}

	go waitFor(func() {
		<-w
		e, _ := ctg.Watch(key)
		if e.Key != key || e.Value != newValue {
			t.Errorf("Entry mismatch for key %v: expected (key=%v, value=%v), but got (key=%v, value=%v)", key, key, newValue, e.Key, e.Value)
		}
	}, done)

	upsertDummyEntry(db, ct, key, newValue)

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("ctg.Watch() failed to detect changes")
	}
}

func TestConfigTableGetter_Get(t *testing.T) {
	db, ct, ctg := getterFixture(t)

	upsertDummyEntry(db, ct, key, value)

	entry, found := ctg.Get(key)
	if !found || entry.Value != value {
		t.Errorf("Failed to retrieve the expected entry for key %v: found=%v, expected value=%v, got value=%v", key, found, value, entry.Value)
	}
}

func TestConfigTableGetter_Init(t *testing.T) {
	db, ct, ctg := getterFixture(t)

	done := make(chan bool)
	go waitFor(ctg.Init, done)

	upsertDummyEntry(db, ct, key, value)

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("ctg.Init() failed to initialize")
	}
}

func getterFixture(t *testing.T) (*statedb.DB, statedb.RWTable[*ConfigEntry], ConfigTableGetter) {
	var (
		db    *statedb.DB
		table statedb.RWTable[*ConfigEntry]
		ctb   ConfigTableGetter
	)

	h := hive.New(
		cell.Provide(
			NewConfigTable,
			ProvideConfigTableGetter,
			func(table statedb.RWTable[*ConfigEntry]) statedb.Table[*ConfigEntry] {
				return table
			}),

		cell.Invoke(
			func(t statedb.RWTable[*ConfigEntry], db_ *statedb.DB, ctb_ ConfigTableGetter) error {
				table = t
				db = db_
				ctb = ctb_
				return nil
			},
			statedb.RegisterTable[*ConfigEntry],
		),
	)

	ctx := context.Background()
	tLog := hivetest.Logger(t)
	if err := h.Start(tLog, ctx); err != nil {
		t.Fatalf("starting hive encountered: %s", err)
	}
	t.Cleanup(func() {
		if err := h.Stop(tLog, ctx); err != nil {
			t.Fatalf("stoping hive encountered: %s", err)
		}
	})
	return db, table, ctb
}

func waitFor(f func(), done chan bool) {
	f()
	done <- true
}

func upsertDummyEntry(db *statedb.DB, table statedb.RWTable[*ConfigEntry], k string, v string) {
	txn := db.WriteTxn(table)
	defer txn.Commit()

	entry := NewConfigEntry(k, v)
	_, _, _ = table.Insert(txn, &entry)
}
