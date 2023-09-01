// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mapreconciler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/cilium/ebpf"
	"k8s.io/client-go/util/workqueue"
)

func newMapReconciler[E Pair[K, V], K Marshalable, V any](
	m Map[K, V],
	db *statedb.DB,
	tbl statedb.Table[E],
	pkIndex statedb.Index[E, K],
	jobGroup job.Group,
	options options[E, K, V],
) *mapReconciler[E, K, V] {
	return &mapReconciler[E, K, V]{
		m:          m,
		db:         db,
		tbl:        tbl,
		pkIndex:    pkIndex,
		jobGroup:   jobGroup,
		options:    options,
		retryQueue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}
}

type mapReconciler[E Pair[K, V], K Marshalable, V any] struct {
	m          Map[K, V]
	db         *statedb.DB
	tbl        statedb.Table[E]
	pkIndex    statedb.Index[E, K]
	jobGroup   job.Group
	retryQueue workqueue.RateLimitingInterface
	options    options[E, K, V]
}

// Start implements hive.Hook.
func (m *mapReconciler[E, K, V]) Start(ctx hive.HookContext) error {
	// Only do work if the map is enabled.
	if m.m.Enabled() {
		m.jobGroup.Add(
			job.OneShot(fmt.Sprintf("map-%s-reconciler", m.m.Name()), m.reconcile),
			job.OneShot(fmt.Sprintf("map-%s-retirer", m.m.Name()), m.Retirer),
		)
	}

	return nil
}

// Start implements hive.Hook.
func (m *mapReconciler[E, K, V]) Stop(ctx hive.HookContext) error {
	m.retryQueue.ShutDown()
	return nil
}

func (m *mapReconciler[E, K, V]) newDeleteTracker() (*statedb.DeleteTracker[E], error) {
	txn := m.db.WriteTxn(m.tbl)
	tracker, err := m.tbl.DeleteTracker(txn, fmt.Sprintf("map-%s", m.m.Name()))
	if err != nil {
		txn.Abort()
		return nil, fmt.Errorf("delete tracker: %w", err)
	}
	txn.Commit()

	return tracker, nil
}

// reconcile is the main reconciliation loop for the map reconciler.
func (m *mapReconciler[E, K, V]) reconcile(ctx context.Context) error {
	tracker, err := m.newDeleteTracker()
	if err != nil {
		return err
	}

	// On startup always perform a full reconciliation so we always start from a known state.
	rev := m.fullReconciliation(ctx)

	limitTicker := time.NewTicker(m.options.partialReconcileRatelimit)
	fullReconcileTicker := time.NewTicker(m.options.fullReconciliationInterval)

	for {
		// limit the reconciliation rate, better to batch changes than to loop
		// for every individual change.
		<-limitTicker.C

		var invalidate <-chan struct{}
		rev, invalidate = m.partialReconciliation(ctx, tracker, rev)

		select {
		case <-invalidate:
			continue

		case <-fullReconcileTicker.C:
			rev = m.fullReconciliation(ctx)

		case <-ctx.Done():
			return nil
		}
	}
}

// partialReconciliation processes the changes in the delete tracker and applies them to the BPF map.
// It doesn't reconcile values that have not changed and doesn't check the map for rouge values, this makes it fast.
func (m *mapReconciler[E, K, V]) partialReconciliation(ctx context.Context, tracker *statedb.DeleteTracker[E], revIn uint64) (uint64, <-chan struct{}) {
	rxn := m.db.ReadTxn()
	rev, invalidate, err := tracker.Process(rxn, revIn, func(entry E, deleted bool, _ uint64) error {
		if deleted {
			err := m.m.Delete(entry.Key())
			// If we error, retry this key later, don't hold up the delete tracker.
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				m.retryQueue.AddRateLimited(entry.Key())
				return nil
			}

			// clear the key from the retry queue (if present) since we just performed an delete without error
			m.retryQueue.Forget(entry.Key())

			return nil
		}

		// If a custom map entry equal function is provided, use it to determine if the entry should be updated.
		if m.options.mapEntryEqual != nil {
			v, err := m.m.Lookup(entry.Key())
			if err == nil {
				if m.options.mapEntryEqual(entry, entry.Key(), v) {
					return nil
				}
			}
		}

		err := m.m.Put(entry.Key(), entry.Value())
		// If we error, retry this key later, don't hold up the delete tracker.
		if err != nil {
			m.retryQueue.AddRateLimited(entry.Key())
			return nil
		}

		// clear the key from the retry queue (if present) since we just performed an update without error
		m.retryQueue.Forget(entry.Key())

		return nil
	})
	if err != nil {
		panic(fmt.Errorf("delete tracker bug: %w", err))
	}

	return rev, invalidate
}

func (m *mapReconciler[E, K, V]) fullReconciliation(ctx context.Context) uint64 {
	rxn := m.db.ReadTxn()
	rev := m.tbl.Revision(rxn)
	iter, _ := m.tbl.All(rxn)
	_ = statedb.ProcessEach(iter, func(entry E, _ uint64) error {
		// If a custom map entry equal function is provided, use it to determine if the entry should be updated.
		if m.options.mapEntryEqual != nil {
			v, err := m.m.Lookup(entry.Key())
			if err == nil {
				if m.options.mapEntryEqual(entry, entry.Key(), v) {
					return nil
				}
			}
		}

		err := m.m.Put(entry.Key(), entry.Value())
		// If we error, retry this key later, don't hold up the delete tracker.
		if err != nil {
			m.retryQueue.AddRateLimited(entry.Key())
			return nil
		}

		// clear the key from the retry queue (if present) since we just performed an update without error
		m.retryQueue.Forget(entry.Key())

		return nil
	})

	// Delete any keys in the map that are not in the stateDB table.
	mIter := m.m.Iterate()
	var (
		v V
		k K
	)
	// we are not allowed to delete while iterating, so we collect the keys to delete and delete
	// them after the iteration
	var toDelete []K
	for mIter.Next(&k, &v) {
		_, _, found := m.tbl.First(rxn, m.pkIndex.Query(k))
		if !found {
			toDelete = append(toDelete, k)
		}
	}
	for _, k := range toDelete {
		err := m.m.Delete(k)
		// If we error, retry this key later, don't hold up the delete tracker.
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			m.retryQueue.AddRateLimited(k)
			continue
		}

		// clear the key from the retry queue (if present) since we just performed an update without error
		m.retryQueue.Forget(k)
	}

	return rev
}

func (m *mapReconciler[E, K, V]) Retirer(ctx context.Context) error {
	done := ctx.Done()
	for {
		// Loop until the ctx expires
		select {
		case <-done:
			return nil
		default:
		}

		// This will block until an item is available or the queue is shutdown.
		// Shutdown happens when Stop() is called so this should not block on cell shutdown.
		item, shutdown := m.retryQueue.Get()
		if shutdown {
			return nil
		}

		k, ok := item.(K)
		if !ok {
			// This should never happen, but if it does, handle it instead of panicing.
			m.retryQueue.Forget(k)
			continue
		}

		// Check what the latest state of the key is in the stateDB table.
		rxn := m.db.ReadTxn()
		e, _, found := m.tbl.First(rxn, m.pkIndex.Query(k))
		if found {
			// If a custom map entry equal function is provided, use it to determine if the entry should be updated.
			if m.options.mapEntryEqual != nil {
				v, err := m.m.Lookup(e.Key())
				if err == nil {
					if m.options.mapEntryEqual(e, e.Key(), v) {
						return nil
					}
				}
			}

			if err := m.m.Put(k, e.Value()); err != nil {
				m.retryQueue.AddRateLimited(k)
				continue
			}

			m.retryQueue.Forget(k)
			continue
		}

		if err := m.m.Delete(k); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				m.retryQueue.AddRateLimited(k)
				continue
			}
		}

		m.retryQueue.Forget(k)
	}
}
