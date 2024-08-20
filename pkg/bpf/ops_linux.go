// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"encoding"
	"errors"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"
)

// ErrMapNotOpened is returned when the MapOps is used with a BPF map that is not open yet.
// In general this should be avoided and the map should be opened in a start hook before
// the reconciler. If the map won't be used then the reconciler should not be started.
var ErrMapNotOpened = errors.New("BPF map has not been opened")

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
	m *Map
}

func NewMapOps[KV KeyValue](m *Map) reconciler.Operations[KV] {
	ops := &mapOps[KV]{m}
	return ops
}

func (ops *mapOps[KV]) withMap(do func(m *ebpf.Map) error) error {
	ops.m.lock.RLock()
	defer ops.m.lock.RUnlock()
	if ops.m.m == nil {
		return ErrMapNotOpened
	}
	return do(ops.m.m)
}

// Delete implements reconciler.Operations.
func (ops *mapOps[KV]) Delete(ctx context.Context, txn statedb.ReadTxn, entry KV) error {
	return ops.withMap(func(m *ebpf.Map) error {
		err := ops.m.m.Delete(entry.BinaryKey())
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// Silently ignore deletions of non-existing keys.
			return nil
		}
		return err
	})
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

// Prune BPF map values that do not exist in the table.
func (ops *mapOps[KV]) Prune(ctx context.Context, txn statedb.ReadTxn, iter statedb.Iterator[KV]) error {
	return ops.withMap(func(m *ebpf.Map) error {
		desiredKeys := sets.New(statedb.Collect(statedb.Map(iter, func(kv KV) string { return ops.toStringKey(kv) }))...)

		// We need to collect the keys to prune first, as it is not safe to
		// delete entries while iterating
		keysToPrune := [][]byte{}
		mapIter := &keyIterator{m, nil, nil, m.MaxEntries()}
		for key := mapIter.Next(); key != nil; key = mapIter.Next() {
			if !desiredKeys.Has(string(key)) {
				keysToPrune = append(keysToPrune, key)
			}
		}

		var errs []error
		for _, key := range keysToPrune {
			if err := m.Delete(key); err != nil {
				errs = append(errs, err)
			}
		}

		errs = append(errs, mapIter.Err())
		return errors.Join(errs...)
	})
}

// Update the BPF map value to match with the object in the desired state table.
func (ops *mapOps[KV]) Update(ctx context.Context, txn statedb.ReadTxn, entry KV) error {
	return ops.withMap(func(m *ebpf.Map) error {
		return m.Put(entry.BinaryKey(), entry.BinaryValue())
	})
}
