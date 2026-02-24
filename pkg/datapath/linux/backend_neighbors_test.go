// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_test

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestBackendNeighborSync(t *testing.T) {
	// Ignore all the currently running goroutines spawned
	// by prior tests or by package init() functions.
	goleakOpt := testutils.GoleakIgnoreCurrent()
	t.Cleanup(func() { testutils.GoleakVerifyNone(t, goleakOpt) })

	var (
		db             *statedb.DB
		backends       statedb.RWTable[*loadbalancer.Backend]
		forwardableIPs statedb.Table[*neighbor.ForwardableIP]
	)

	h := hive.New(
		cell.Provide(
			loadbalancer.NewBackendsTable,
			statedb.RWTable[*loadbalancer.Backend].ToTable,
		),
		neighbor.ForwardableIPCell,
		cell.Provide(neighbor.NewCommonTestConfig(true, false)),
		linux.BackendNeighborSyncCell,
		cell.Invoke(func(db_ *statedb.DB, backends_ statedb.RWTable[*loadbalancer.Backend], forwardableIPs_ statedb.Table[*neighbor.ForwardableIP]) {
			db = db_
			backends = backends_
			forwardableIPs = forwardableIPs_
		}),
	)
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
	})

	var addr1, addr2 loadbalancer.L3n4Addr
	addr1.ParseFromString("1.0.0.1:80/TCP")
	addr2.ParseFromString("2.0.0.2:80/TCP")

	wtxn := db.WriteTxn(backends)
	backends.Insert(wtxn, &loadbalancer.Backend{Address: addr1})
	backends.Insert(wtxn, &loadbalancer.Backend{Address: addr2})
	wtxn.Commit()

	requireHasAddress := func(addr loadbalancer.L3n4Addr, invert bool) func() bool {
		return func() bool {
			rx := db.ReadTxn()
			for fip := range forwardableIPs.All(rx) {
				if fip.IP == addr.Addr() {
					return !invert
				}
			}

			return invert
		}
	}

	require.Eventually(t, requireHasAddress(addr1, false), 5*time.Second, 100*time.Millisecond)
	require.Eventually(t, requireHasAddress(addr2, false), 5*time.Second, 100*time.Millisecond)

	wtxn = db.WriteTxn(backends)
	backends.DeleteAll(wtxn)
	wtxn.Commit()

	require.Eventually(t, requireHasAddress(addr1, true), 5*time.Second, 100*time.Millisecond)
	require.Eventually(t, requireHasAddress(addr2, true), 5*time.Second, 100*time.Millisecond)
}
