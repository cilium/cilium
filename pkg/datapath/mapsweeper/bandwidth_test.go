// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mapsweeper

import (
	"context"
	"iter"
	"maps"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	bandwidthTypes "github.com/cilium/cilium/pkg/datapath/linux/bandwidth/types"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/promise"
)

// fakeThrottleMap stands in for the cilium_throttle BPF map: it holds the
// bandwidth (in bytes per second) of each entry, keyed like the BPF map.
type fakeThrottleMap struct {
	mu      lock.Mutex
	entries map[bwmap.EdtIDKey]uint64
}

func (m *fakeThrottleMap) dump() map[bwmap.EdtIDKey]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.entries)
}

func (m *fakeThrottleMap) Update(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, e bwmap.Edt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[e.EdtIDKey] = e.BytesPerSecond
	return nil
}

func (m *fakeThrottleMap) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, e bwmap.Edt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, e.EdtIDKey)
	return nil
}

func (m *fakeThrottleMap) Prune(_ context.Context, _ statedb.ReadTxn, objs iter.Seq2[bwmap.Edt, statedb.Revision]) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	desired := map[bwmap.EdtIDKey]struct{}{}
	for e := range objs {
		desired[e.EdtIDKey] = struct{}{}
	}
	maps.DeleteFunc(m.entries, func(k bwmap.EdtIDKey, _ uint64) bool {
		_, ok := desired[k]
		return !ok
	})
	return nil
}

// blockingRestorer completes endpoint restoration once restored is closed.
type blockingRestorer struct {
	restored chan struct{}
}

func (r *blockingRestorer) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.restored:
		return nil
	}
}

func (r *blockingRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return r.wait(ctx)
}

func (r *blockingRestorer) WaitForEndpointRestore(ctx context.Context) error {
	return r.wait(ctx)
}

func (r *blockingRestorer) WaitForInitialPolicy(ctx context.Context) error {
	return r.wait(ctx)
}

func TestBandwidthEdtPruneWaitsForEndpointRestore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		restorer := &blockingRestorer{restored: make(chan struct{})}

		restoredEp := bwmap.EdtIDKey{EndpointID: 1}
		staleEp := bwmap.EdtIDKey{EndpointID: 2}

		// Entries left in cilium_throttle by the previous agent run. Endpoint
		// 1 is restored, endpoint 2 no longer exists.
		throttleMap := &fakeThrottleMap{
			entries: map[bwmap.EdtIDKey]uint64{restoredEp: 1000, staleEp: 2000},
		}

		var (
			db   *statedb.DB
			edts statedb.RWTable[bwmap.Edt]
		)
		h := hive.New(
			job.Cell,
			cell.Provide(
				statedb.New,
				cell.NewSimpleHealth,
				func(registry job.Registry, health cell.Health) job.Group {
					return registry.NewGroup(health)
				},
			),
			cell.Module("test", "test",
				cell.Provide(
					bwmap.NewEdtTable,
					func() bandwidthTypes.Config {
						return bandwidthTypes.Config{EnableBandwidthManager: true}
					},
					func() promise.Promise[endpointstate.Restorer] {
						resolver, p := promise.New[endpointstate.Restorer]()
						resolver.Resolve(restorer)
						return p
					},
				),
				cell.Invoke(
					registerBandwidthEdtInitializer,
					func(p reconciler.Params, tbl statedb.RWTable[bwmap.Edt]) error {
						_, err := reconciler.Register(
							p,
							tbl,
							func(e bwmap.Edt) bwmap.Edt { return e },
							func(e bwmap.Edt, s reconciler.Status) bwmap.Edt {
								e.Status = s
								return e
							},
							func(e bwmap.Edt) reconciler.Status { return e.Status },
							throttleMap,
							nil,
							// Reconcile changes as soon as they are committed.
							reconciler.WithRoundLimits(1000, rate.NewLimiter(rate.Inf, 1)),
						)
						return err
					},
					func(d *statedb.DB, tbl statedb.RWTable[bwmap.Edt]) {
						db, edts = d, tbl
					},
				),
			),
		)

		log := hivetest.Logger(t)
		require.NoError(t, h.Start(log, t.Context()))
		t.Cleanup(func() { require.NoError(t, h.Stop(log, context.Background())) })

		synctest.Wait()
		require.Equal(t,
			map[bwmap.EdtIDKey]uint64{restoredEp: 1000, staleEp: 2000},
			throttleMap.dump(),
			"cilium_throttle must not be pruned before endpoint restoration")

		// The restored endpoint re-applies its bandwidth limit.
		wtxn := db.WriteTxn(edts)
		_, _, err := edts.Insert(wtxn, bwmap.NewEdt(restoredEp.EndpointID, restoredEp.Direction, 3000, 0))
		require.NoError(t, err)
		wtxn.Commit()

		synctest.Wait()
		require.Equal(t,
			map[bwmap.EdtIDKey]uint64{restoredEp: 3000, staleEp: 2000},
			throttleMap.dump(),
			"cilium_throttle must not be pruned before endpoint restoration")

		close(restorer.restored)

		synctest.Wait()
		require.Equal(t,
			map[bwmap.EdtIDKey]uint64{restoredEp: 3000},
			throttleMap.dump(),
			"stale cilium_throttle entries must be pruned after endpoint restoration")
	})
}
