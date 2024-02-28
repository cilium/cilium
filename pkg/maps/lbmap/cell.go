package lbmap

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
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
		// TODO: constructors for Service*Map
		NewService4Table,
		NewService6Table,
	),

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

	if cfg.EnableIPv4 {
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return Service4MapV2.OpenOrCreate()
			},
		})
	}

	if cfg.EnableIPv6 {
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return Service6MapV2.OpenOrCreate()
			},
		})
	}

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
		FullReconcilationInterval: 0, // Full reconciliation disabled
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Minute,
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
