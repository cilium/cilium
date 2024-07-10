// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental_test

import (
	"context"
	"encoding/binary"
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/source"
)

type testParams struct {
	cell.In

	DB     *statedb.DB
	Writer *experimental.Writer

	ServiceTable  statedb.Table[*experimental.Service]
	FrontendTable statedb.Table[*experimental.Frontend]
	BackendTable  statedb.Table[*experimental.Backend]
}

func fixture(t testing.TB) (p testParams) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

	h := hive.New(
		cell.Config(experimental.DefaultConfig),
		experimental.TablesCell,

		cell.Invoke(func(p_ testParams) { p = p_ }),
	)

	hive.AddConfigOverride(h, func(cfg *experimental.Config) {
		cfg.EnableExperimentalLB = true
	})

	require.NoError(t, h.Start(log, context.TODO()))
	t.Cleanup(func() {
		h.Stop(log, context.TODO())
	})
	return p
}

func intToAddr(i int) types.AddrCluster {
	var addr [4]byte
	binary.BigEndian.PutUint32(addr[:], 0x0100_0000+uint32(i))
	addrCluster, _ := types.AddrClusterFromIP(addr[:])
	return addrCluster
}

func TestServices_Service_UpsertDelete(t *testing.T) {
	p := fixture(t)
	name := loadbalancer.ServiceName{Namespace: "test", Name: "test1"}
	addrCluster := intToAddr(1)
	frontend := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal)

	// Add a dump of the state if the test fails. Note that we abort
	// the delete write transactions so they're not visible via this.
	t.Cleanup(func() {
		if t.Failed() {
			p.Writer.DebugDump(p.DB.ReadTxn(), os.Stdout)
		}
	})

	// UpsertServiceAndFrontends
	{
		wtxn := p.Writer.WriteTxn()

		err := p.Writer.UpsertServiceAndFrontends(
			wtxn,
			&experimental.Service{
				Name:   name,
				Source: source.Kubernetes,
			},
			&experimental.Frontend{
				ServiceName: name,
				Address:     frontend,
				Type:        loadbalancer.SVCTypeClusterIP,
			},
		)
		require.NoError(t, err, "UpsertService failed")
		wtxn.Commit()
	}

	// Lookup service and frontend
	{
		txn := p.DB.ReadTxn()
		assert.Equal(t, 1, p.ServiceTable.NumObjects(txn))
		assert.Equal(t, 1, p.FrontendTable.NumObjects(txn))

		svc, _, found := p.ServiceTable.Get(txn, experimental.ServiceNameIndex.Query(name))
		if assert.True(t, found, "Service not found by name") {
			assert.NotNil(t, svc)
			assert.Equal(t, name, svc.Name, "Service name not equal")
		}

		fe, _, found := p.FrontendTable.Get(txn, experimental.FrontendAddressIndex.Query(frontend))
		if assert.True(t, found, "Frontend not found by addr") {
			assert.NotNil(t, fe)
			assert.Equal(t, name, fe.ServiceName, "Service name not equal")
			assert.Equal(t, reconciler.StatusKindPending, fe.Status.Kind, "Expected pending status")
		}
		fe, _, found = p.FrontendTable.Get(txn, experimental.FrontendServiceIndex.Query(name))
		if assert.True(t, found, "Frontend not found by name") {
			assert.NotNil(t, fe)
			assert.Equal(t, name, fe.ServiceName, "Service name not equal")
		}
	}

	// Deletion by name
	{
		wtxn := p.Writer.WriteTxn()
		assert.Equal(t, 1, p.ServiceTable.NumObjects(wtxn))

		err := p.Writer.DeleteServiceAndFrontends(wtxn, name)
		assert.NoError(t, err, "DeleteService failed")

		_, _, found := p.ServiceTable.Get(wtxn, experimental.ServiceNameIndex.Query(name))
		assert.False(t, found, "Service found after delete")

		_, _, found = p.FrontendTable.Get(wtxn, experimental.FrontendServiceIndex.Query(name))
		assert.False(t, found, "Frontend found after delete")

		wtxn.Abort()
	}

	// Deletion by source
	{
		wtxn := p.Writer.WriteTxn()
		require.Equal(t, 1, p.ServiceTable.NumObjects(wtxn))
		err := p.Writer.DeleteServicesBySource(wtxn, source.Kubernetes)
		require.NoError(t, err, "DeleteServicesBySource failed")

		_, _, found := p.ServiceTable.Get(wtxn, experimental.ServiceNameIndex.Query(name))
		assert.False(t, found, "Service found after delete")

		wtxn.Abort()
	}
}

func TestServices_Backend_UpsertDelete(t *testing.T) {
	p := fixture(t)

	// Add a dump of the state if the test fails. Note that we abort
	// the delete write transactions so they're not visible via this.
	t.Cleanup(func() {
		if t.Failed() {
			p.Writer.DebugDump(p.DB.ReadTxn(), os.Stdout)
		}
	})

	name1 := loadbalancer.ServiceName{Namespace: "test", Name: "test1"}
	name2 := loadbalancer.ServiceName{Namespace: "test", Name: "test2"}

	nextAddr := 0
	mkAddr := func(port uint16) loadbalancer.L3n4Addr {
		nextAddr++
		addrCluster := intToAddr(nextAddr)
		return *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, port, loadbalancer.ScopeExternal)
	}
	frontend := mkAddr(3000)

	// Add a service with [name1] for backends to refer to.
	// [name2] is left non-existing.
	{
		wtxn := p.Writer.WriteTxn()

		err := p.Writer.UpsertServiceAndFrontends(
			wtxn,
			&experimental.Service{
				Name:   name1,
				Source: source.Kubernetes,
			},
			&experimental.Frontend{
				Address: frontend,
				Type:    loadbalancer.SVCTypeClusterIP,
			})

		require.NoError(t, err, "UpsertService failed")
		wtxn.Commit()
	}

	fe, _, found := p.FrontendTable.Get(p.DB.ReadTxn(), experimental.FrontendServiceIndex.Query(name1))
	require.True(t, found, "Lookup frontend failed")

	// UpsertBackends
	beAddr1, beAddr2, beAddr3 := mkAddr(4000), mkAddr(5000), mkAddr(6000)
	{
		wtxn := p.Writer.WriteTxn()

		// Add two backends for [name1].
		p.Writer.UpsertBackends(
			wtxn,
			name1,
			source.Kubernetes,
			&loadbalancer.Backend{
				L3n4Addr: beAddr1,
				State:    loadbalancer.BackendStateActive,
			},
			&loadbalancer.Backend{
				L3n4Addr: beAddr2,
				State:    loadbalancer.BackendStateActive,
			},
		)

		// Add a backend for the non-existing [name2].
		p.Writer.UpsertBackends(
			wtxn,
			name2,
			source.Kubernetes,
			&loadbalancer.Backend{
				L3n4Addr: beAddr3,
				State:    loadbalancer.BackendStateActive,
			},
		)

		wtxn.Commit()
	}

	// Lookup
	{
		txn := p.DB.ReadTxn()

		// By address
		for _, addr := range []loadbalancer.L3n4Addr{beAddr1, beAddr2, beAddr3} {
			be, _, found := p.BackendTable.Get(txn, experimental.BackendAddrIndex.Query(addr))
			if assert.True(t, found, "Backend not found with address %s", addr) {
				assert.True(t, be.L3n4Addr.DeepEqual(&addr), "Backend address %s does not match %s", be.L3n4Addr, addr)
			}
		}

		// By service
		bes := statedb.Collect(p.BackendTable.List(txn, experimental.BackendServiceIndex.Query(name1)))
		require.Len(t, bes, 2)
		require.True(t, bes[0].L3n4Addr.DeepEqual(&beAddr1))
		require.True(t, bes[1].L3n4Addr.DeepEqual(&beAddr2))

		// Backends for [name2] can be found even though the service doesn't exist (yet).
		bes = statedb.Collect(p.BackendTable.List(txn, experimental.BackendServiceIndex.Query(name2)))
		require.Len(t, bes, 1)
		require.True(t, bes[0].L3n4Addr.DeepEqual(&beAddr3))
	}

	// GetBackendsForFrontend
	{
		txn := p.DB.ReadTxn()

		bes := statedb.Collect(experimental.GetBackendsForFrontend(txn, p.BackendTable, fe))
		require.Len(t, bes, 2)
		require.True(t, bes[0].L3n4Addr.DeepEqual(&beAddr1))
		require.True(t, bes[1].L3n4Addr.DeepEqual(&beAddr2))
	}

	// ReleaseBackend
	{
		wtxn := p.Writer.WriteTxn()

		// Release the [name1] reference to [beAddr1].
		require.Equal(t, 3, p.BackendTable.NumObjects(wtxn))
		err := p.Writer.ReleaseBackend(wtxn, name1, beAddr1)
		require.NoError(t, err, "ReleaseBackend failed")

		// [beAddr2] remains for [name1].
		bes := statedb.Collect(experimental.GetBackendsForFrontend(wtxn, p.BackendTable, fe))
		require.Len(t, bes, 1)
		require.True(t, bes[0].L3n4Addr.DeepEqual(&beAddr2))

		wtxn.Abort()
	}

	// DeleteBackendsBySource
	{
		wtxn := p.Writer.WriteTxn()

		require.Equal(t, 3, p.BackendTable.NumObjects(wtxn))
		err := p.Writer.DeleteBackendsBySource(wtxn, source.Kubernetes)
		require.NoError(t, err, "DeleteBackendsBySource failed")
		iter := p.BackendTable.All(wtxn)
		require.Len(t, statedb.Collect(iter), 0)

		// No backends remain for the service.
		bes := statedb.Collect(experimental.GetBackendsForFrontend(wtxn, p.BackendTable, fe))
		require.Len(t, bes, 0)

		wtxn.Abort()
	}
}
