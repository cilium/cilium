// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
)

func Test_PendingInitializers_DefersUpdateAndPrune(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)

	db := statedb.New()

	nodeAddrs, err := tables.NewNodeAddressTable(db)
	require.NoError(t, err)

	fes, err := loadbalancer.NewFrontendsTable(loadbalancer.DefaultConfig, db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(fes)
	completeInit := fes.RegisterInitializer(wtxn, "clustermesh")
	wtxn.Commit()

	maglevCfg, err := maglev.UserConfig{
		TableSize: 1021,
		HashSeed:  maglev.DefaultHashSeed,
	}.ToConfig()
	require.NoError(t, err)
	mglv := maglev.New(maglevCfg, lc)

	cfg, _ := loadbalancer.NewConfig(log, loadbalancer.DefaultUserConfig, &option.DaemonConfig{})

	ops := newBPFOps(bpfOpsParams{
		Lifecycle: lc,
		Log:       log,
		Config:    cfg,
		ExternalConfig: loadbalancer.ExternalConfig{
			ZoneMapper: &option.DaemonConfig{},
			EnableIPv4: true,
			EnableIPv6: true,
		},
		LBMaps:        maps.NewFakeLBMaps(),
		Maglev:        mglv,
		DB:            db,
		NodeAddresses: nodeAddrs,
		Frontends:     fes,
	})

	fe := &loadbalancer.Frontend{
		FrontendParams: loadbalancer.FrontendParams{
			Address: loadbalancer.NewL3n4Addr(
				loadbalancer.TCP,
				types.MustParseAddrCluster("10.0.0.1"),
				80,
				loadbalancer.ScopeExternal,
			),
			Type: loadbalancer.SVCTypeClusterIP,
		},
		Backends: func(yield func(*loadbalancer.Backend, statedb.Revision) bool) {},
	}

	rtxn := db.ReadTxn()

	err = ops.Update(context.Background(), rtxn, 0, fe)
	require.ErrorIs(t, err, errInitializersPending)

	prevPruneCount := ops.pruneCount.Load()

	err = ops.Prune(context.Background(), rtxn, nil)
	require.NoError(t, err)
	require.Equal(t, prevPruneCount, ops.pruneCount.Load(),
		"pruneCount must not advance while initializers are pending")

	wtxn = db.WriteTxn(fes)
	completeInit(wtxn)
	wtxn.Commit()

	rtxn = db.ReadTxn()
	err = ops.Prune(context.Background(), rtxn, nil)
	require.NoError(t, err)
	require.Equal(t, prevPruneCount+1, ops.pruneCount.Load(),
		"pruneCount must advance once initializers are complete")
}

func Test_InitializersPending_NilFrontendsTable(t *testing.T) {
	ops := &BPFOps{}
	require.False(t, ops.initializersPending(nil))
}
