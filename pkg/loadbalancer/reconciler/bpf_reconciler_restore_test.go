// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	sreconciler "github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
)

func newRestoreEnv(t *testing.T) (*BPFOps, maps.LBMaps, statedb.RWTable[*loadbalancer.Frontend]) {
	t.Helper()
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)

	maglevCfg, err := maglev.UserConfig{TableSize: 1021, HashSeed: maglev.DefaultHashSeed}.ToConfig()
	require.NoError(t, err, "ToConfig")
	extCfg := loadbalancer.ExternalConfig{
		ZoneMapper:           &option.DaemonConfig{},
		EnableIPv4:           true,
		EnableIPv6:           true,
		KubeProxyReplacement: true,
	}
	cfg, err := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, loadbalancer.DeprecatedConfig{}, &option.DaemonConfig{})
	require.NoError(t, err)
	cfg.LBAlgorithm = loadbalancer.LBAlgorithmRandom

	lbmaps := maps.NewFakeLBMaps()

	db := statedb.New()
	nodeAddrs, err := tables.NewNodeAddressTable()
	require.NoError(t, err)
	require.NoError(t, db.RegisterTable(nodeAddrs))
	frontends, err := loadbalancer.NewFrontendsTable(cfg, db)
	require.NoError(t, err)

	ops := newBPFOps(bpfOpsParams{
		Lifecycle:      lc,
		Log:            log,
		Config:         cfg,
		ExternalConfig: extCfg,
		LBMaps:         lbmaps,
		Maglev:         maglev.New(maglevCfg, lc),
		DB:             db,
		NodeAddresses:  nodeAddrs,
	})
	return ops, lbmaps, frontends
}

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
	ops, lbmaps, table := newRestoreEnv(t)
	frontend := func(addr string) *loadbalancer.Frontend {
		svc := baseService
		fe := baseFrontend
		fe.Address = parseAddrPort(addr)
		fe.Type = ClusterIP
		fe.Service = &svc
		fe.Backends = concatBe(fe.Backends, *baseBackend.GetInstance(svc.Name), 1)
		return &fe
	}
	update := func(fe *loadbalancer.Frontend) {
		require.NoError(t, ops.Update(t.Context(), ops.db.ReadTxn(), 0, fe))
	}
	require.NoError(t, ops.ResetAndRestore())
	first := frontend("172.18.0.1:80")
	last := frontend("172.18.0.2:80")
	stale := frontend("172.18.0.3:80")
	update(first)
	update(last)
	want := maps.DumpLBMaps(lbmaps, false, nil)
	update(stale)
	require.NoError(t, ops.ResetAndRestore())
	recorder := &restoreDeletionRecorder{LBMaps: lbmaps}
	ops.LBMaps = recorder
	txn := ops.db.WriteTxn(table)
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
		cell.Provide(func() *statedb.DB { return ops.db }, cell.NewSimpleHealth,
			func(registry job.Registry, health cell.Health, lifecycle cell.Lifecycle) job.Group {
				return registry.NewGroup(health, lifecycle)
			}),
		cell.Module("test", "Restore pruning regression", cell.Invoke(func(p sreconciler.Params) error {
			_, err := sreconciler.Register(p, table, (*loadbalancer.Frontend).Clone,
				func(fe *loadbalancer.Frontend, status sreconciler.Status) *loadbalancer.Frontend {
					fe.Status = status
					return fe
				},
				func(fe *loadbalancer.Frontend) sreconciler.Status { return fe.Status }, ops, nil,
				sreconciler.WithRoundLimits(1, rate.NewLimiter(rate.Every(time.Millisecond), 1)),
				sreconciler.WithPruning(time.Hour), sreconciler.WithRefreshing(0, nil))
			return err
		})))
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, t.Context()))
	defer func() { require.NoError(t, h.Stop(log, context.Background())) }()
	require.Eventually(t, func() bool { return ops.pruneCount.Load() > 0 },
		5*time.Second, time.Millisecond, "automatic startup prune must run")
	ops.mu.Lock()
	defer ops.mu.Unlock()
	require.NotContains(t, recorder.deleted, first.Address)
	require.NotContains(t, recorder.deleted, last.Address)
	require.Contains(t, recorder.deleted, stale.Address)
	require.Equal(t, want, maps.DumpLBMaps(lbmaps, false, nil))
}
