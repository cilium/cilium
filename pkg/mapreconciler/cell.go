// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mapreconciler

import (
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"

	"github.com/sirupsen/logrus"
)

// Marshalable is an interface for types that can be marshaled into a byte slice.
type Marshalable interface {
	Marshal() []byte
}

// Pair is an interface for types that can be used as a key-value pair.
// The key is Marshalable so it can be indexed in the state database.
type Pair[K Marshalable, V any] interface {
	Key() K
	Value() V
}

// Iterator is a typed iterator around ebpf.Iterator, to guarantee type type safety.
type Iterator[K Marshalable, V any] interface {
	Next(k *K, v *V) bool
	Err() error
}

// Map describes the API we require an map to have if it whishes to be reconciled.
type Map[K Marshalable, V any] interface {
	Name() string
	Enabled() bool
	Lookup(K) (V, error)
	Put(K, V) error
	Delete(K) error
	Iterate() Iterator[K, V]
}

// NewReconciler creates a new reconciler for a BPF map. The reconciler will reconcile the state of a
// stateDB table containing `E` with a BPF map having a key of type `K` and a value of type `V`.
//
// The reconciler will watch the table for changes and apply them to the BPF map. And it periodically
// will perform a full reconciliation of the BPF map with the stateDB table.
//
// The reconciler requires a `Map[K, V]`, `statedb.Table[E]`, and `statedb.Index[E, K]` to be present
// in hive.
func NewReconciler[E Pair[K, V], K Marshalable, V any](opts ...Opt[E, K, V]) cell.Cell {
	return cell.Invoke(func(
		lifecycle hive.Lifecycle,
		log logrus.FieldLogger,
		m Map[K, V],
		db *statedb.DB,
		tbl statedb.Table[E],
		pkIndex statedb.Index[E, K],
		jr job.Registry,
	) {
		options := defaultOptions[E, K, V]()
		for _, opt := range opts {
			opt.apply(&options)
		}

		group := jr.NewGroup(job.WithLogger(log))
		mapReconciler := newMapReconciler[E, K, V](m, db, tbl, pkIndex, group, options)
		lifecycle.Append(mapReconciler)
		lifecycle.Append(group)
	})
}

// PrimaryKeyIndex generates a primary key index for a stateDB table containing `E` which will index on the bytes
// of the map key.
func PrimaryKeyIndex[E Pair[K, V], K Marshalable, V any]() statedb.Index[E, K] {
	return statedb.Index[E, K]{
		Name: "key",
		FromObject: func(entry E) index.KeySet {
			return index.NewKeySet(entry.Key().Marshal())
		},
		FromKey: func(k K) []byte {
			return k.Marshal()
		},
		Unique: true,
	}
}

type options[E Pair[K, V], K Marshalable, V any] struct {
	partialReconcileRatelimit  time.Duration
	fullReconciliationInterval time.Duration
	mapEntryEqual              func(e E, k K, v V) bool
}

func defaultOptions[E Pair[K, V], K Marshalable, V any]() options[E, K, V] {
	return options[E, K, V]{
		partialReconcileRatelimit:  100 * time.Millisecond,
		fullReconciliationInterval: 5 * time.Minute,
	}
}

// Opt is an option for a reconciler.
type Opt[E Pair[K, V], K Marshalable, V any] interface {
	apply(*options[E, K, V])
}

type optFunc[E Pair[K, V], K Marshalable, V any] func(*options[E, K, V])

func (f optFunc[E, K, V]) apply(o *options[E, K, V]) {
	f(o)
}

// WithPartialReconcileRatelimit sets the ratelimit for partial reconciliations.
// The default value is 100ms if not set.
func WithPartialReconcileRatelimit[E Pair[K, V], K Marshalable, V any](d time.Duration) Opt[E, K, V] {
	return optFunc[E, K, V](func(o *options[E, K, V]) {
		o.partialReconcileRatelimit = d
	})
}

// WithFullReconciliationInterval sets the interval for full reconciliations.
// The default value is 5 minutes if not set.
func WithFullReconciliationInterval[E Pair[K, V], K Marshalable, V any](d time.Duration) Opt[E, K, V] {
	return optFunc[E, K, V](func(o *options[E, K, V]) {
		o.fullReconciliationInterval = d
	})
}

// WithMapEntryEqual sets the function used to compare a map entry with a key-value pair.
// If set, the reconciler will perform a lookup before updating any object and will use the provided
// function to compare the stateDB entry with the BPF map entry. If the function returns true, the
// reconciler will not update the BPF map entry.
//
// By default, no lookup is performed and the BPF map entry is always updated if the stateDB entry
// has changed.
func WithMapEntryEqual[E Pair[K, V], K Marshalable, V any](f func(e E, k K, v V) bool) Opt[E, K, V] {
	return optFunc[E, K, V](func(o *options[E, K, V]) {
		o.mapEntryEqual = f
	})
}
