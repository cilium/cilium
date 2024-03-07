package lbmap

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

var Cell = cell.Module(
	"lbmap",
	"Load-balancer BPF maps and reconciliation",

	cell.Provide(
		initMaps,
		newLBMap,
	),

	cell.ProvidePrivate(
		job.Registry.NewGroup,

		NewService4Table,
		NewService6Table,
		NewBackend4Table,
		NewBackend6Table,
		NewRevNat4Table,
		NewRevNat6Table,
	),

	// These are each wrapped into modules currently as the
	// reconciler uses the module ID as the label in metrics.
	// TBD whether this is the pattern we want or whether we
	// should use some other (user provided?) identifier as
	// the metrics label. This probably isn't too bad, one
	// might often want to construct bunch of things privately
	// (e.g. the reconciler ops etc.) so wrapping inside small
	// modules seems a-ok.
	cell.Module(
		"service4",
		"IPv4 service map reconciliation",
		cell.Invoke(registerService4Reconciler),
	),

	cell.Module(
		"service6",
		"IPv6 service map reconciliation",
		cell.Invoke(registerService6Reconciler),
	),

	cell.Module(
		"backend4",
		"IPv4 backend map reconciliation",
		cell.Invoke(registerBackend4Reconciler),
	),

	cell.Module(
		"backend6",
		"IPv6 backend map reconciliation",
		cell.Invoke(registerBackend6Reconciler),
	),

	cell.Module(
		"revnat4",
		"IPv4 revnat map reconciliation",
		cell.Invoke(registerRevNat4Reconciler),
	),

	cell.Module(
		"revnat6",
		"IPv6 revnat map reconciliation",
		cell.Invoke(registerRevNat6Reconciler),
	),

	cell.Invoke(
		restoreServices,
		restoreBackends,

		pressureMetrics,

		func(g job.Group, lc cell.Lifecycle) { lc.Append(g) },
	),
)

type mapsInitialized struct{}

func initMaps(lc cell.Lifecycle, cfg *option.DaemonConfig) mapsInitialized {
	// FIXME: Get rid of the global BPF map variables and turn this into a constructor that returns the BPF maps!
	lbmapInitParams := InitParams{
		IPv4: cfg.EnableIPv4,
		IPv6: cfg.EnableIPv6,

		MaxSockRevNatMapEntries:  cfg.SockRevNatEntries,
		ServiceMapMaxEntries:     cfg.LBMapEntries,
		BackEndMapMaxEntries:     cfg.LBMapEntries,
		RevNatMapMaxEntries:      cfg.LBMapEntries,
		AffinityMapMaxEntries:    cfg.LBMapEntries,
		SourceRangeMapMaxEntries: cfg.LBMapEntries,
		MaglevMapMaxEntries:      cfg.LBMapEntries,
	}
	if cfg.LBServiceMapEntries > 0 {
		lbmapInitParams.ServiceMapMaxEntries = cfg.LBServiceMapEntries
	}
	if cfg.LBBackendMapEntries > 0 {
		lbmapInitParams.BackEndMapMaxEntries = cfg.LBBackendMapEntries
	}
	if cfg.LBRevNatEntries > 0 {
		lbmapInitParams.RevNatMapMaxEntries = cfg.LBRevNatEntries
	}
	if cfg.LBAffinityMapEntries > 0 {
		lbmapInitParams.AffinityMapMaxEntries = cfg.LBAffinityMapEntries
	}
	if cfg.LBSourceRangeMapEntries > 0 {
		lbmapInitParams.SourceRangeMapMaxEntries = cfg.LBSourceRangeMapEntries
	}
	if cfg.LBMaglevMapEntries > 0 {
		lbmapInitParams.MaglevMapMaxEntries = cfg.LBMaglevMapEntries
	}
	Init(lbmapInitParams)

	// Add a start hook to open/create the maps we need in the reconcilers
	// (we need this so we can call .Map() to grab *ebpf.Map.
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if cfg.EnableIPv4 {
				if err := Service4MapV2.OpenOrCreate(); err != nil {
					return err
				}
				if err := Backend4MapV3.OpenOrCreate(); err != nil {
					return err
				}
				if err := RevNat4Map.OpenOrCreate(); err != nil {
					return err
				}
			}
			if cfg.EnableIPv6 {
				if err := Service6MapV2.OpenOrCreate(); err != nil {
					return err
				}
				if err := Backend6MapV3.OpenOrCreate(); err != nil {
					return err
				}
				if err := RevNat6Map.OpenOrCreate(); err != nil {
					return err
				}
			}

			return nil
		},
	})

	return mapsInitialized{}
}

func newLBMap(p params, _ mapsInitialized) types.LBMap {
	return New(p)
}

type reconcilerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       logrus.FieldLogger
	DB        *statedb.DB
	Jobs      job.Registry
	Metrics   *reconciler.Metrics
	ModuleId  cell.ModuleID
	Scope     cell.Scope

	DaemonConfig    *option.DaemonConfig
	MapsInitialized mapsInitialized
}

func serviceReconcilerParams(tbl statedb.RWTable[*Service], ops reconciler.Operations[*Service], p reconcilerParams) reconciler.Params[*Service] {
	cfg := reconciler.Config[*Service]{
		FullReconcilationInterval: time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   10 * time.Second,
		IncrementalRoundSize:      1000, // Reconcile up to 1000 services before updating status
		GetObjectStatus:           (*Service).GetStatus,
		WithObjectStatus:          (*Service).WithStatus,
		Operations:                ops,
	}
	return reconciler.Params[*Service]{
		Config:    cfg,
		Lifecycle: p.Lifecycle,
		Log:       p.Log,
		DB:        p.DB,
		Table:     tbl,
		Jobs:      p.Jobs,
		Metrics:   p.Metrics,
		ModuleId:  p.ModuleId,
		Scope:     p.Scope,
	}
}

// FIXME: Too much copy-pasta below.

func registerService4Reconciler(tbl Service4Table, p reconcilerParams) error {
	if !p.DaemonConfig.EnableIPv4 {
		return nil
	}
	lc := &cell.DefaultLifecycle{}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// The Map() method only works after OpenOrCreate, e.g. after initMaps
			// start hook. We'll likely need to find a better way of dealing with
			// this if there's more cases where we can't construct the ops before
			// starting. One slightly cleaner way would be to not have reconciler.New()
			// append to the lifecycle and thus wouldn't need the DefaultLifecycle hack here.
			// Though here the issue is mostly the bpf map mess and not having access to *ebpf.Map
			// before starting.
			ops, _ := ops.NewMapOps[*Service](Service4MapV2.Map())
			params := serviceReconcilerParams(tbl, ops, p)
			params.Lifecycle = lc
			err := reconciler.Register(params)
			if err != nil {
				return err
			}
			return lc.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return lc.Stop(ctx)
		},
	})
	return nil
}

func registerService6Reconciler(tbl Service6Table, p reconcilerParams) error {
	if !p.DaemonConfig.EnableIPv6 {
		return nil
	}
	lc := &cell.DefaultLifecycle{}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			ops, _ := ops.NewMapOps[*Service](Service6MapV2.Map())
			params := serviceReconcilerParams(tbl, ops, p)
			params.Lifecycle = lc
			err := reconciler.Register(params)
			if err != nil {
				return err
			}
			return lc.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return lc.Stop(ctx)
		},
	})
	return nil
}

// ----

func backendReconcilerParams(tbl statedb.RWTable[*BackendKV], ops reconciler.Operations[*BackendKV], p reconcilerParams) reconciler.Params[*BackendKV] {
	cfg := reconciler.Config[*BackendKV]{
		FullReconcilationInterval: time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   10 * time.Second,
		IncrementalRoundSize:      1000, // Reconcile up to 1000 backends before updating status
		GetObjectStatus:           (*BackendKV).GetStatus,
		WithObjectStatus:          (*BackendKV).WithStatus,
		Operations:                ops,
	}
	return reconciler.Params[*BackendKV]{
		Config:    cfg,
		Lifecycle: p.Lifecycle,
		Log:       p.Log,
		DB:        p.DB,
		Table:     tbl,
		Jobs:      p.Jobs,
		Metrics:   p.Metrics,
		ModuleId:  p.ModuleId,
		Scope:     p.Scope,
	}
}

func registerBackend4Reconciler(tbl Backend4Table, p reconcilerParams) error {
	if !p.DaemonConfig.EnableIPv4 {
		return nil
	}
	lc := &cell.DefaultLifecycle{}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// The Map() method only works after OpenOrCreate, e.g. after initMaps
			// start hook. We'll likely need to find a better way of dealing with
			// this if there's more cases where we can't construct the ops before
			// starting. One slightly cleaner way would be to not have reconciler.New()
			// append to the lifecycle and thus wouldn't need the DefaultLifecycle hack here.
			// Though here the issue is mostly the bpf map mess and not having access to *ebpf.Map
			// before starting.
			ops, _ := ops.NewMapOps[*BackendKV](Backend4MapV3.Map())
			params := backendReconcilerParams(tbl, ops, p)
			params.Lifecycle = lc
			err := reconciler.Register(params)
			if err != nil {
				return err
			}
			return lc.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return lc.Stop(ctx)
		},
	})
	return nil
}

func registerBackend6Reconciler(tbl Backend6Table, p reconcilerParams) error {
	if !p.DaemonConfig.EnableIPv6 {
		return nil
	}
	lc := &cell.DefaultLifecycle{}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			ops, _ := ops.NewMapOps[*BackendKV](Backend6MapV3.Map())
			params := backendReconcilerParams(tbl, ops, p)
			params.Lifecycle = lc
			err := reconciler.Register(params)
			if err != nil {
				return err
			}
			return lc.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return lc.Stop(ctx)
		},
	})
	return nil
}

// ------

func revNatReconcilerParams(tbl statedb.RWTable[*RevNat], ops reconciler.Operations[*RevNat], p reconcilerParams) reconciler.Params[*RevNat] {
	cfg := reconciler.Config[*RevNat]{
		FullReconcilationInterval: time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   10 * time.Second,
		IncrementalRoundSize:      1000, // Reconcile up to 1000 revNats before updating status
		GetObjectStatus:           (*RevNat).GetStatus,
		WithObjectStatus:          (*RevNat).WithStatus,
		Operations:                ops,
	}
	return reconciler.Params[*RevNat]{
		Config:    cfg,
		Lifecycle: p.Lifecycle,
		Log:       p.Log,
		DB:        p.DB,
		Table:     tbl,
		Jobs:      p.Jobs,
		Metrics:   p.Metrics,
		ModuleId:  p.ModuleId,
		Scope:     p.Scope,
	}
}

func registerRevNat4Reconciler(tbl RevNat4Table, p reconcilerParams) error {
	if !p.DaemonConfig.EnableIPv4 {
		return nil
	}
	lc := &cell.DefaultLifecycle{}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// The Map() method only works after OpenOrCreate, e.g. after initMaps
			// start hook. We'll likely need to find a better way of dealing with
			// this if there's more cases where we can't construct the ops before
			// starting. One slightly cleaner way would be to not have reconciler.New()
			// append to the lifecycle and thus wouldn't need the DefaultLifecycle hack here.
			// Though here the issue is mostly the bpf map mess and not having access to *ebpf.Map
			// before starting.
			ops, _ := ops.NewMapOps[*RevNat](RevNat4Map.Map())
			params := revNatReconcilerParams(tbl, ops, p)
			params.Lifecycle = lc
			err := reconciler.Register(params)
			if err != nil {
				return err
			}
			return lc.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return lc.Stop(ctx)
		},
	})
	return nil
}

func registerRevNat6Reconciler(tbl RevNat6Table, p reconcilerParams) error {
	if !p.DaemonConfig.EnableIPv6 {
		return nil
	}
	lc := &cell.DefaultLifecycle{}
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			ops, _ := ops.NewMapOps[*RevNat](RevNat6Map.Map())
			params := revNatReconcilerParams(tbl, ops, p)
			params.Lifecycle = lc
			err := reconciler.Register(params)
			if err != nil {
				return err
			}
			return lc.Start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return lc.Stop(ctx)
		},
	})
	return nil
}

// ------

func restoreServices(lc cell.Lifecycle, cfg *option.DaemonConfig, db *statedb.DB, tbl4 Service4Table, tbl6 Service6Table, _ mapsInitialized) {
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {

			txn := db.WriteTxn(tbl4, tbl6)
			defer txn.Commit()

			if cfg.EnableIPv4 {
				err := Service4MapV2.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
					svcKey := k.(ServiceKey)
					svcValue := v.(ServiceValue)
					tbl4.Insert(txn, &Service{
						K:      svcKey,
						V:      svcValue,
						Status: reconciler.StatusDone(),
					})
				})
				if err != nil {
					return err
				}
			}

			if cfg.EnableIPv6 {
				err := Service6MapV2.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
					svcKey := k.(ServiceKey)
					svcValue := v.(ServiceValue)
					tbl6.Insert(txn, &Service{
						K:      svcKey,
						V:      svcValue,
						Status: reconciler.StatusDone(),
					})
				})
				if err != nil {
					return err
				}
			}
			return nil
		}})
}

func restoreBackends(lc cell.Lifecycle, cfg *option.DaemonConfig, db *statedb.DB, tbl4 Backend4Table, tbl6 Backend6Table, _ mapsInitialized) {
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {

			txn := db.WriteTxn(tbl4, tbl6)
			defer txn.Commit()

			if cfg.EnableIPv4 {
				err := Backend4MapV3.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
					beKey := k.(BackendKey)
					beValue := v.(BackendValue)
					tbl4.Insert(txn, &BackendKV{
						K:      beKey,
						V:      beValue,
						Status: reconciler.StatusDone(),
					})
				})
				if err != nil {
					return err
				}
			}

			if cfg.EnableIPv6 {
				err := Backend6MapV3.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
					beKey := k.(BackendKey)
					beValue := v.(BackendValue).ToHost()
					tbl6.Insert(txn, &BackendKV{
						K:      beKey,
						V:      beValue,
						Status: reconciler.StatusDone(),
					})
				})
				if err != nil {
					return err
				}
			}
			return nil
		}})
}

func pressureMetrics(g job.Group, db *statedb.DB, s4 Service4Table, b4 Backend4Table, _ mapsInitialized) {
	s4m := metrics.NewBPFMapPressureGauge(Service4MapV2.NonPrefixedName(), 0.0)
	b4m := metrics.NewBPFMapPressureGauge(Backend4Map.NonPrefixedName(), 0.0)

	g.Add(job.Timer(
		"pressure-metrics",
		func(ctx context.Context) error {
			txn := db.ReadTxn()
			s4m.Set(float64(s4.NumObjects(txn)) / float64(Service4MapV2.MaxEntries()))
			b4m.Set(float64(b4.NumObjects(txn)) / float64(Backend4Map.MaxEntries()))
			return nil
		},
		10*time.Second,
	))

}
