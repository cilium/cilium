// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	sreconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
)

// restoreDeletionRecorder observes transient master removal even if Update later repairs it.
type restoreDeletionRecorder struct {
	maps.LBMaps
	deleted []loadbalancer.L3n4Addr
}

func (m *restoreDeletionRecorder) DeleteService(key maps.ServiceKey) error {
	if err := m.LBMaps.DeleteService(key); err != nil {
		return err
	}
	key = key.ToHost()
	if key.GetBackendSlot() == 0 {
		m.deleted = append(m.deleted, svcKeyToAddr(key))
	}
	return nil
}

func TestRestorePruneAfterInitialReconciliation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newBPFOpsLeakTestFixture(t, nil, nil, func(cfg *loadbalancer.Config, _ *loadbalancer.ExternalConfig) {
			cfg.LBAlgorithm = loadbalancer.LBAlgorithmRandom
		})
		frontend := func(addr string) *loadbalancer.Frontend {
			fe := newLeakTestFrontend(parseAddrPort(addr), ClusterIP, baseBackend)
			return &fe
		}
		update := func(fe *loadbalancer.Frontend) {
			require.NoError(t, e.ops.Update(t.Context(), e.db.ReadTxn(), 0, fe))
		}
		require.NoError(t, e.ops.ResetAndRestore())
		first := frontend("172.18.0.1:80")
		last := frontend("172.18.0.2:80")
		stale := frontend("172.18.0.3:80")
		update(first)
		update(last)
		want := maps.DumpLBMaps(e.lbmaps, false, nil)
		update(stale)
		require.NoError(t, e.ops.ResetAndRestore())
		recorder := &restoreDeletionRecorder{LBMaps: e.lbmaps}
		e.ops.LBMaps = recorder
		table := e.ops.frontends.(statedb.RWTable[*loadbalancer.Frontend])
		txn := e.ops.db.WriteTxn(table)
		initialized := table.RegisterInitializer(txn, "test")
		for _, fe := range []*loadbalancer.Frontend{first, last} {
			fe = fe.Clone()
			fe.Status = sreconciler.StatusPending()
			_, _, err := table.Insert(txn, fe)
			require.NoError(t, err)
		}
		initialized(txn)
		txn.Commit()
		h := hive.New(job.Cell,
			cell.Provide(func() *statedb.DB { return e.ops.db }, cell.NewSimpleHealth,
				func(registry job.Registry, health cell.Health) job.Group { return registry.NewGroup(health) }),
			cell.Module("test", "Restore pruning regression", cell.Invoke(func(p sreconciler.Params) error {
				_, err := sreconciler.Register(p, table, (*loadbalancer.Frontend).Clone,
					func(fe *loadbalancer.Frontend, status sreconciler.Status) *loadbalancer.Frontend {
						fe.Status = status
						return fe
					},
					func(fe *loadbalancer.Frontend) sreconciler.Status { return fe.Status }, e.ops, nil,
					sreconciler.WithRoundLimits(1, rate.NewLimiter(1, 1)),
					sreconciler.WithPruning(time.Hour), sreconciler.WithRefreshing(0, nil))
				return err
			})))
		log := hivetest.Logger(t)
		require.NoError(t, h.Start(log, t.Context()))
		defer func() { require.NoError(t, h.Stop(log, context.Background())) }()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		require.Positive(t, e.ops.pruneCount.Load(), "automatic startup prune must run")
		require.NotContains(t, recorder.deleted, first.Address)
		require.NotContains(t, recorder.deleted, last.Address)
		require.Contains(t, recorder.deleted, stale.Address)
		require.Equal(t, want, maps.DumpLBMaps(e.lbmaps, false, nil))
	})
}
