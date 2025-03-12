// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"iter"
)

// AnyTable allows any-typed access to a StateDB table. This is intended
// for building generic tooling for accessing the table and should be
// avoided if possible.
type AnyTable struct {
	Meta TableMeta
}

func (t AnyTable) NumObjects(txn ReadTxn) int {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.Meta, PrimaryIndexPos)
	return indexTxn.Len()
}

func (t AnyTable) All(txn ReadTxn) iter.Seq2[any, Revision] {
	all, _ := t.AllWatch(txn)
	return all
}

func (t AnyTable) AllWatch(txn ReadTxn) (iter.Seq2[any, Revision], <-chan struct{}) {
	indexTxn := txn.getTxn().mustIndexReadTxn(t.Meta, PrimaryIndexPos)
	return partSeq[any](indexTxn.Iterator()), indexTxn.RootWatch()
}

func (t AnyTable) UnmarshalYAML(data []byte) (any, error) {
	return t.Meta.unmarshalYAML(data)
}

func (t AnyTable) Insert(txn WriteTxn, obj any) (old any, hadOld bool, err error) {
	var iobj object
	iobj, hadOld, _, err = txn.getTxn().insert(t.Meta, Revision(0), obj)
	if hadOld {
		old = iobj.data
	}
	return
}

func (t AnyTable) Delete(txn WriteTxn, obj any) (old any, hadOld bool, err error) {
	var iobj object
	iobj, hadOld, err = txn.getTxn().delete(t.Meta, Revision(0), obj)
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
	if itxn.unique {
		obj, _, ok := itxn.Get(rawKey)
		return obj.data, obj.revision, ok, nil
	}
	// For non-unique indexes we need to prefix search and make sure to fully
	// match the secondary key.
	iter, _ := itxn.Prefix(rawKey)
	for {
		k, obj, ok := iter.Next()
		if !ok {
			break
		}
		if nonUniqueKey(k).secondaryLen() == len(rawKey) {
			return obj.data, obj.revision, true, nil
		}
	}
	return nil, 0, false, nil
}

func (t AnyTable) Prefix(txn ReadTxn, index string, key string) (iter.Seq2[any, Revision], error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, err
	}
	iter, _ := itxn.Prefix(rawKey)
	if itxn.unique {
		return partSeq[any](iter), nil
	}
	return nonUniqueSeq[any](iter, true, rawKey), nil
}

func (t AnyTable) LowerBound(txn ReadTxn, index string, key string) (iter.Seq2[any, Revision], error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, err
	}
	iter := itxn.LowerBound(rawKey)
	if itxn.unique {
		return partSeq[any](iter), nil
	}
	return nonUniqueLowerBoundSeq[any](iter, rawKey), nil
}

func (t AnyTable) List(txn ReadTxn, index string, key string) (iter.Seq2[any, Revision], error) {
	itxn, rawKey, err := t.queryIndex(txn, index, key)
	if err != nil {
		return nil, err
	}
	iter, _ := itxn.Prefix(rawKey)
	if itxn.unique {
		// Unique index means that there can be only a single matching object.
		// Doing a Get() is more efficient than constructing an iterator.
		value, _, ok := itxn.Get(rawKey)
		return func(yield func(any, Revision) bool) {
			if ok {
				yield(value.data, value.revision)
			}
		}, nil
	}
	return nonUniqueSeq[any](iter, false, rawKey), nil
}

func (t AnyTable) queryIndex(txn ReadTxn, index string, key string) (indexReadTxn, []byte, error) {
	indexer := t.Meta.getIndexer(index)
	if indexer == nil {
		return indexReadTxn{}, nil, fmt.Errorf("invalid index %q", index)
	}
	rawKey, err := indexer.fromString(key)
	if err != nil {
		return indexReadTxn{}, nil, err
	}
	itxn, err := txn.getTxn().indexReadTxn(t.Meta, indexer.pos)
	return itxn, rawKey, err
}

func (t AnyTable) Changes(txn WriteTxn) (anyChangeIterator, error) {
	return t.Meta.anyChanges(txn)
}

func (t AnyTable) TableHeader() []string {
	zero := t.Meta.proto()
	if tw, ok := zero.(TableWritable); ok {
		return tw.TableHeader()
	}
	return nil
}

func (t AnyTable) Proto() any {
	return t.Meta.proto()
}
