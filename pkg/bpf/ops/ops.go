// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ops

import (
	"bytes"
	"context"
	"encoding"
	"errors"

	cilium_ebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type KeyValue interface {
	Key() encoding.BinaryMarshaler
	Value() encoding.BinaryMarshaler
}

type mapOps[KV KeyValue] struct {
	m *ebpf.Map
}

func NewMapOps[KV KeyValue](m *ebpf.Map) (reconciler.Operations[KV], reconciler.BatchOperations[KV]) {
	ops := &mapOps[KV]{m}
	return ops, ops
}

// Delete implements reconciler.Operations.
func (ops *mapOps[KV]) Delete(ctx context.Context, txn statedb.ReadTxn, entry KV) error {
	return ops.m.Delete(entry.Key())
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
	key, _ := kv.Key().MarshalBinary()
	return string(key)
}

func (ops *mapOps[KV]) equalValue(b []byte, kv KV) bool {
	value, _ := kv.Value().MarshalBinary()
	return bytes.Equal(b, value)
}

// Prune implements reconciler.Operations.
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

// Update implements reconciler.Operations.
func (ops *mapOps[KV]) Update(ctx context.Context, txn statedb.ReadTxn, entry KV, changed *bool) error {
	if changed != nil {
		var value []byte
		err := ops.m.Lookup(entry.Key(), &value)
		if err != nil {
			if errors.Is(err, cilium_ebpf.ErrKeyNotExist) {
				*changed = true
			} else {
				return err
			}
		} else {
			*changed = !ops.equalValue(value, entry)
		}
		if *changed {
			return ops.m.Put(entry.Key(), entry.Value())
		}
		return nil
	} else {
		return ops.m.Put(entry.Key(), entry.Value())
	}
}

type sliceMarshaler []encoding.BinaryMarshaler

func (sm sliceMarshaler) MarshalBinary() ([]byte, error) {
	out := []byte{}
	for _, m := range sm {
		b, _ := m.MarshalBinary()
		out = append(out, b...)
	}
	return out, nil
}

func (ops *mapOps[KV]) UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[KV]) {
	// FIXME: Get rid of copying. Should be able to do this zero-copy!
	keys := make([]encoding.BinaryMarshaler, 0, len(batch))
	for _, e := range batch {
		keys = append(keys, e.Object.Key())
	}

	values := make([]encoding.BinaryMarshaler, 0, len(batch))
	for _, e := range batch {
		values = append(values, e.Object.Value())
	}
	n, err := ops.m.BatchUpdate(sliceMarshaler(keys), sliceMarshaler(values), &cilium_ebpf.BatchOptions{
		ElemFlags: unix.BPF_ANY,
	})
	for i := n; i < len(batch); i++ {
		batch[i].Result = err
	}
}

func (ops *mapOps[KV]) DeleteBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[KV]) {
	buf := make([]encoding.BinaryMarshaler, 0, len(batch))
	for _, e := range batch {
		buf = append(buf, e.Object.Key())
	}
	n, err := ops.m.BatchDelete(sliceMarshaler(buf), nil)
	if errors.Is(err, cilium_ebpf.ErrKeyNotExist) {
		err = nil
	}
	for i := n; i < len(batch); i++ {
		batch[i].Result = err
	}
}
