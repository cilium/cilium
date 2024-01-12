package datapath

import (
	"bytes"
	"context"
	"encoding"
	"errors"

	cilium_ebpf "github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

type KeyValue interface {
	Key() encoding.BinaryMarshaler
	Value() encoding.BinaryMarshaler
}

type mapOps[KV KeyValue] struct {
	m   *ebpf.Map
	log logrus.FieldLogger
}

func NewMapOps[KV KeyValue](m *ebpf.Map, log logrus.FieldLogger) reconciler.Operations[KV] {
	return &mapOps[KV]{m, log}
}

// Delete implements reconciler.Operations.
func (ops *mapOps[KV]) Delete(ctx context.Context, txn statedb.ReadTxn, entry KV) (err error) {
	defer func() {
		ops.log.Infof("%T.Delete: err=%v", ops, err)
	}()
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
	var (
		errs    []error
		deleted int
	)
	mapIter := &keyIterator{ops.m, nil, nil, ops.m.MaxEntries()}
	for key := mapIter.Next(); key != nil; key = mapIter.Next() {
		if !desiredKeys.Has(string(key)) {
			if err := ops.m.Delete(key); err != nil {
				errs = append(errs, err)
			}
			deleted++
		}
	}
	errs = append(errs, mapIter.Err())
	ops.log.Infof("%T.Prune: errs=%v, deleted=%d", ops, errs, deleted)
	return errors.Join(errs...)
}

// Update implements reconciler.Operations.
func (ops *mapOps[KV]) Update(ctx context.Context, txn statedb.ReadTxn, entry KV, changed *bool) (err error) {
	if changed != nil {
		// If changed is not nil, then we're doing full reconciliation
		// and should check whether this update resulted in a change.
		// This allows detecting when full reconciliation fixed an
		// issue.

		defer func() {
			ops.log.Infof("%T.Update: err=%v, changed=%v", ops, err, *changed)
		}()

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
		defer func() {
			ops.log.Infof("%T.Update: err=%v", ops, err)
		}()

		return ops.m.Put(entry.Key(), entry.Value())
	}
}
