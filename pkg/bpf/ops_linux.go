// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"bytes"
	"context"
	"encoding"
	"errors"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

// KeyValue is the interface that an BPF map value object must implement.
//
// The object can either store the key and value directly in struct form
// and use StructBinaryMarshaler{}, or it can implement conversion to binary
// form on the fly by implementing BinaryMarshaler by hand.
type KeyValue interface {
	BinaryKey() encoding.BinaryMarshaler
	BinaryValue() encoding.BinaryMarshaler
}

// StructBinaryMarshaler implements a BinaryMarshaler for a struct of
// primitive fields. Same caviats apply as with cilium/ebpf when using a
// struct as key or value.
// Example usage:
//
//	func (x *X) Key() encoding.BinaryMarshaler {
//	  return StructBinaryMarshaler{x}
//	}
type StructBinaryMarshaler struct {
	Target any // pointer to struct
}

func (m StructBinaryMarshaler) MarshalBinary() ([]byte, error) {
	v := reflect.ValueOf(m.Target)
	size := int(v.Type().Elem().Size())
	return unsafe.Slice((*byte)(v.UnsafePointer()), size), nil
}

type mapOps[KV KeyValue] struct {
	m *ebpf.Map
}

func NewMapOps2[KV KeyValue](m *ebpf.Map) reconciler.Operations[KV] {
	ops := &mapOps[KV]{m}
	return ops
}

func NewMapOps[KV KeyValue](m *Map) reconciler.Operations[KV] {
	ops := &mapOps[KV]{m.m}
	return ops
}

// Delete implements reconciler.Operations.
func (ops *mapOps[KV]) Delete(ctx context.Context, txn statedb.ReadTxn, entry KV) error {
	return ops.m.Delete(entry.BinaryKey())
}

type keyIterator struct {
	m          *ebpf.Map
	nextKey    []byte
	err        error
	maxEntries uint32
}

func (it *keyIterator) Err() error {
	return it.err
}

func (it *keyIterator) Next() []byte {
	if it.maxEntries == 0 {
		return nil
	}
	var key []byte
	if it.nextKey == nil {
		key, it.err = it.m.NextKeyBytes(nil)
	} else {
		key, it.err = it.m.NextKeyBytes(it.nextKey)
	}
	if key == nil || it.err != nil {
		return nil
	}
	it.nextKey = key
	it.maxEntries--
	return key
}

func (ops *mapOps[KV]) toStringKey(kv KV) string {
	key, _ := kv.BinaryKey().MarshalBinary()
	return string(key)
}

func (ops *mapOps[KV]) equalValue(b []byte, kv KV) bool {
	value, _ := kv.BinaryValue().MarshalBinary()
	return bytes.Equal(b, value)
}

// Prune BPF map values that do not exist in the table.
func (ops *mapOps[KV]) Prune(ctx context.Context, txn statedb.ReadTxn, iter statedb.Iterator[KV]) error {
	desiredKeys := statedb.CollectSet(statedb.Map(iter, func(kv KV) string { return ops.toStringKey(kv) }))
	var errs []error
	mapIter := &keyIterator{ops.m, nil, nil, ops.m.MaxEntries()}
	for key := mapIter.Next(); key != nil; key = mapIter.Next() {
		if !desiredKeys.Has(string(key)) {
			if err := ops.m.Delete(key); err != nil {
				errs = append(errs, err)
			}
		}
	}
	errs = append(errs, mapIter.Err())
	return errors.Join(errs...)
}

// Update the BPF map value to match with the object in the desired state table.
func (ops *mapOps[KV]) Update(ctx context.Context, txn statedb.ReadTxn, entry KV, changed *bool) error {
	if changed != nil {
		// If changed is set, then we're doing a full reconciliation and we want to track
		// whether the full reconciliation fixes anything. We figure out if a change is
		// necessary by doing a lookup and comparing values.
		var value []byte
		err := ops.m.Lookup(entry.BinaryKey(), &value)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				*changed = true
			} else {
				return err
			}
		} else {
			*changed = !ops.equalValue(value, entry)
		}
		if *changed {
			return ops.m.Put(entry.BinaryKey(), entry.BinaryValue())
		}
		return nil
	} else {
		return ops.m.Put(entry.BinaryKey(), entry.BinaryValue())
	}
}
