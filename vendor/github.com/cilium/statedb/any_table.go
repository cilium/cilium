// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"iter"

	"github.com/cilium/statedb/index"
)

// AnyTable allows any-typed access to a StateDB table. This is intended
// for building generic tooling for accessing the table and should be
// avoided if possible.
type AnyTable struct {
	Meta TableMeta
}

func (t AnyTable) NumObjects(txn ReadTxn) int {
	return txn.mustIndexReadTxn(t.Meta, PrimaryIndexPos).len()
}

func (t AnyTable) All(txn ReadTxn) iter.Seq2[any, Revision] {
	all, _ := t.AllWatch(txn)
	return all
}

func (t AnyTable) AllWatch(txn ReadTxn) (iter.Seq2[any, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t.Meta, PrimaryIndexPos)
	iter, watch := indexTxn.all()
	return func(yield func(any, Revision) bool) {
		iter.All(func(_ []byte, iobj object) bool {
			return yield(iobj.data, iobj.revision)
		})
	}, watch
}

func (t AnyTable) UnmarshalYAML(data []byte) (any, error) {
	return t.Meta.unmarshalYAML(data)
}

func (t AnyTable) Insert(txn WriteTxn, obj any) (old any, hadOld bool, err error) {
	var iobj object
	iobj, hadOld, _, err = txn.unwrap().insert(t.Meta, Revision(0), obj)
	if hadOld {
		old = iobj.data
	}
	return
}

func (t AnyTable) Delete(txn WriteTxn, obj any) (old any, hadOld bool, err error) {
	var iobj object
	iobj, hadOld, err = txn.unwrap().delete(t.Meta, Revision(0), obj)
	if hadOld {
		old = iobj.data
	}
	return
}

func (t AnyTable) Get(txn ReadTxn, index string, key string) (any, Revision, bool, error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, 0, false, err
	}
	obj, _, found := itxn.get(rawKey)
	if found {
		return obj.data, obj.revision, found, nil
	}
	return nil, 0, false, nil
}

func (t AnyTable) Prefix(txn ReadTxn, index string, key string) (iter.Seq2[any, Revision], error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, err
	}
	iter, _ := itxn.prefix(rawKey)
	return objSeq[any](iter), nil
}

func (t AnyTable) LowerBound(txn ReadTxn, index string, key string) (iter.Seq2[any, Revision], error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, err
	}
	iter, _ := itxn.lowerBound(rawKey)
	return objSeq[any](iter), nil
}

func (t AnyTable) List(txn ReadTxn, index string, key string) (iter.Seq2[any, Revision], error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, err
	}
	iter, _ := itxn.list(rawKey)
	return objSeq[any](iter), nil
}

func (t AnyTable) queryIndex(txn ReadTxn, index string, key string) (tableIndexReader, index.Key, error) {
	indexer := t.Meta.getIndexer(index)
	if indexer == nil {
		return nil, nil, fmt.Errorf("invalid index %q", index)
	}
	rawKey, err := indexer.fromString(key)
	if err != nil {
		return nil, nil, err
	}
	itxn, err := txn.indexReadTxn(t.Meta, indexer.pos)
	return itxn, rawKey, err
}

func (t AnyTable) Changes(txn WriteTxn) (anyChangeIterator, error) {
	return t.Meta.anyChanges(txn)
}

func (t AnyTable) TableHeader() []string {
	return t.Meta.tableHeader()
}

func (t AnyTable) TableRow(obj any) []string {
	return t.Meta.tableRowAny(obj)
}
