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
	"github.com/cilium/cilium/pkg/datapath/tables"
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

func fixture(t testing.TB, hooks ...experimental.ServiceHook) (p testParams) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

	type hooksOut struct {
		cell.Out
		Hooks []experimental.ServiceHook `group:"service-hooks,flatten"`
	}
	h := hive.New(
		cell.Config(experimental.DefaultConfig),
		experimental.TablesCell,
		cell.Provide(
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
		),
		cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
		cell.Invoke(func(p_ testParams) { p = p_ }),

		cell.Provide(
			func() hooksOut { return hooksOut{Hooks: hooks} },
		),
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

func TestWriter_Service_UpsertDelete(t *testing.T) {
	serviceUpserts := []*experimental.Service{}
	hookSentinel := uint16(123)

	p := fixture(t, func(txn statedb.ReadTxn, svc *experimental.Service) {
		// Use the "HealthCheckNodePort" field as an indicator that the hook was called.
		svc.HealthCheckNodePort = hookSentinel
		serviceUpserts = append(serviceUpserts, svc)
	})
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

		svc := &experimental.Service{
			Name:   name,
			Source: source.Kubernetes,
		}
		err := p.Writer.UpsertServiceAndFrontends(
			wtxn,
			svc,
			experimental.FrontendParams{
				ServiceName: name,
				Address:     frontend,
				Type:        loadbalancer.SVCTypeClusterIP,
			},
		)
		require.NoError(t, err, "UpsertServiceAndFrontends")

		// Check that the hook gets called.
		require.Len(t, serviceUpserts, 1, "service hook not called")
		require.Equal(t, svc, serviceUpserts[0], "service hook called with wrong object")

		// Updating the service object with UpsertService also results in another hook call.
		origSVC := svc
		svc = &experimental.Service{
			Name:            name,
			Source:          source.Kubernetes,
			SessionAffinity: true,
		}
		old, err := p.Writer.UpsertService(wtxn, svc)
		require.NoError(t, err, "UpsertService")
		require.Equal(t, origSVC, old)
		require.Equal(t, hookSentinel, old.HealthCheckNodePort)

		require.Len(t, serviceUpserts, 2, "service hook not called")
		require.Equal(t, hookSentinel, svc.HealthCheckNodePort)

		wtxn.Commit()
	}

	// Lookup service and frontend
	{
		txn := p.DB.ReadTxn()
		assert.Equal(t, 1, p.ServiceTable.NumObjects(txn))
		assert.Equal(t, 1, p.FrontendTable.NumObjects(txn))

		svc, _, found := p.ServiceTable.Get(txn, experimental.ServiceByName(name))
		if assert.True(t, found, "Service not found by name") {
			assert.NotNil(t, svc)
			assert.Equal(t, name, svc.Name, "Service name not equal")
		}

		fe, _, found := p.FrontendTable.Get(txn, experimental.FrontendByAddress(frontend))
		if assert.True(t, found, "Frontend not found by addr") {
			assert.NotNil(t, fe)
			assert.Equal(t, name, fe.ServiceName, "Service name not equal")
			assert.Equal(t, reconciler.StatusKindPending, fe.Status.Kind, "Expected pending status")
		}
		fe, _, found = p.FrontendTable.Get(txn, experimental.FrontendByServiceName(name))
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

		_, _, found := p.ServiceTable.Get(wtxn, experimental.ServiceByName(name))
		assert.False(t, found, "Service found after delete")

		_, _, found = p.FrontendTable.Get(wtxn, experimental.FrontendByServiceName(name))
		assert.False(t, found, "Frontend found after delete")

		wtxn.Abort()
	}

	// Deletion by source
	{
		wtxn := p.Writer.WriteTxn()
		require.Equal(t, 1, p.ServiceTable.NumObjects(wtxn))
		err := p.Writer.DeleteServicesBySource(wtxn, source.Kubernetes)
		require.NoError(t, err, "DeleteServicesBySource failed")

		_, _, found := p.ServiceTable.Get(wtxn, experimental.ServiceByName(name))
		assert.False(t, found, "Service found after delete")

		wtxn.Abort()
	}
}

func TestWriter_Backend_UpsertDelete(t *testing.T) {
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
	name3 := loadbalancer.ServiceName{Namespace: "test", Name: "test3"}

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
			experimental.FrontendParams{
				Address: frontend,
				Type:    loadbalancer.SVCTypeClusterIP,
			})

		require.NoError(t, err, "UpsertService failed")
		wtxn.Commit()
	}

	fe, _, found := p.FrontendTable.Get(p.DB.ReadTxn(), experimental.FrontendByServiceName(name1))
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
			experimental.BackendParams{
				L3n4Addr: beAddr1,
				State:    loadbalancer.BackendStateActive,
			},
			experimental.BackendParams{
				L3n4Addr: beAddr2,
				State:    loadbalancer.BackendStateActive,
			},
		)

		// Add a backend for the non-existing [name2].
		p.Writer.UpsertBackends(
			wtxn,
			name2,
			source.Kubernetes,
			experimental.BackendParams{
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
			be, _, found := p.BackendTable.Get(txn, experimental.BackendByAddress(addr))
			if assert.True(t, found, "Backend not found with address %s", addr) {
				assert.True(t, be.L3n4Addr.DeepEqual(&addr), "Backend address %s does not match %s", be.L3n4Addr, addr)
			}
		}

		// By service
		bes := statedb.Collect(p.BackendTable.List(txn, experimental.BackendByServiceName(name1)))
		require.Len(t, bes, 2)
		require.True(t, bes[0].L3n4Addr.DeepEqual(&beAddr1))
		require.True(t, bes[1].L3n4Addr.DeepEqual(&beAddr2))

		// Backends for [name2] can be found even though the service doesn't exist (yet).
		bes = statedb.Collect(p.BackendTable.List(txn, experimental.BackendByServiceName(name2)))
		require.Len(t, bes, 1)
		require.True(t, bes[0].L3n4Addr.DeepEqual(&beAddr3))
	}

	// SetBackendHealth
	{

		wtxn := p.Writer.WriteTxn()

		be, _, _ := p.BackendTable.Get(wtxn, experimental.BackendByAddress(beAddr1))
		require.Equal(t, loadbalancer.BackendStateActive, be.State)

		err := p.Writer.SetBackendHealth(wtxn, beAddr1, false)
		require.NoError(t, err, "SetBackendHealth")

		be, _, _ = p.BackendTable.Get(wtxn, experimental.BackendByAddress(beAddr1))
		require.Equal(t, loadbalancer.BackendStateQuarantined, be.State)

		err = p.Writer.SetBackendHealth(wtxn, beAddr1, true)
		require.NoError(t, err, "SetBackendHealth")

		be, _, _ = p.BackendTable.Get(wtxn, experimental.BackendByAddress(beAddr1))
		require.Equal(t, loadbalancer.BackendStateActive, be.State)

		// Marking the backend terminating will cause health updates to be ignored.
		p.Writer.UpsertBackends(wtxn, name2, source.Kubernetes,
			experimental.BackendParams{
				L3n4Addr: beAddr1,
				State:    loadbalancer.BackendStateTerminating,
			},
		)

		err = p.Writer.SetBackendHealth(wtxn, beAddr1, false)
		require.NoError(t, err, "SetBackendHealth")

		be, _, _ = p.BackendTable.Get(wtxn, experimental.BackendByAddress(beAddr1))
		require.Equal(t, loadbalancer.BackendStateTerminating, be.State)

		// Adding another active instance to the backend won't change the
		// computed state.
		p.Writer.UpsertBackends(wtxn, name3, source.Kubernetes,
			experimental.BackendParams{
				L3n4Addr: beAddr1,
				State:    loadbalancer.BackendStateActive,
			},
		)

		be, _, _ = p.BackendTable.Get(wtxn, experimental.BackendByAddress(beAddr1))
		require.Equal(t, loadbalancer.BackendStateTerminating, be.State)
		require.Equal(t, 3, be.Instances.Len()) // name1, name2, name3

		// Removing the "terminating" instance will not change the state, e.g.
		// when a backend has been marked terminating by any instances it'll stay
		// terminating until removed.
		p.Writer.ReleaseBackend(wtxn, name2, beAddr1)
		be, _, _ = p.BackendTable.Get(wtxn, experimental.BackendByAddress(beAddr1))
		require.Equal(t, 2, be.Instances.Len()) // name1, name3
		require.Equal(t, loadbalancer.BackendStateTerminating, be.State)

		wtxn.Abort()
	}

	// ReleaseBackend
	{
		wtxn := p.Writer.WriteTxn()

		// Release the [name1] reference to [beAddr1].
		require.Equal(t, 3, p.BackendTable.NumObjects(wtxn))
		err := p.Writer.ReleaseBackend(wtxn, name1, beAddr1)
		require.NoError(t, err, "ReleaseBackend failed")

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
		require.Len(t, fe.Backends, 0)

		wtxn.Abort()
	}
}

// TestWriter_Initializers checks that all tables managed by Writer are only initialized
// when all registered initializers have completed. The table initialization is a signal
// to the reconciler to initiate pruning.
func TestWriter_Initializers(t *testing.T) {
	p := fixture(t)

	complete1 := p.Writer.RegisterInitializer("test1")
	complete2 := p.Writer.RegisterInitializer("test2")

	wtxn := p.Writer.WriteTxn()
	addr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(123), 12345, loadbalancer.ScopeExternal)
	name := loadbalancer.ServiceName{Name: "test", Namespace: "test"}
	err := p.Writer.UpsertServiceAndFrontends(
		wtxn,
		&experimental.Service{
			Name:   name,
			Source: source.Kubernetes,
		},
		experimental.FrontendParams{
			ServiceName: name,
			Address:     addr,
			Type:        loadbalancer.SVCTypeClusterIP,
		},
	)
	require.NoError(t, err, "UpsertServiceAndFrontends")
	wtxn.Commit()

	txn := p.DB.ReadTxn()
	firstTxn := txn
	require.Equal(t, 1, p.FrontendTable.NumObjects(txn), "expected one object")
	require.NotEmpty(t, p.FrontendTable.PendingInitializers(txn), "expected frontends to be uninitialized")
	require.NotEmpty(t, p.BackendTable.PendingInitializers(txn), "expected backends to be uninitialized")
	require.NotEmpty(t, p.ServiceTable.PendingInitializers(txn), "expected services to be uninitialized")

	wtxn = p.Writer.WriteTxn()
	complete1(wtxn)
	wtxn.Commit()

	// Still uninitialized as one initializer remaining.
	txn = p.DB.ReadTxn()
	require.NotEmpty(t, p.FrontendTable.PendingInitializers(txn), "expected frontends to be uninitialized")
	require.NotEmpty(t, p.BackendTable.PendingInitializers(txn), "expected backends to be uninitialized")
	require.NotEmpty(t, p.ServiceTable.PendingInitializers(txn), "expected services to be uninitialized")

	wtxn = p.Writer.WriteTxn()
	complete2(wtxn)
	wtxn.Commit()

	txn = p.DB.ReadTxn()
	require.Empty(t, p.FrontendTable.PendingInitializers(txn), "expected frontends to be initialized")
	require.Empty(t, p.BackendTable.PendingInitializers(txn), "expected backends to be initialized")
	require.Empty(t, p.ServiceTable.PendingInitializers(txn), "expected services to be initialized")

	// The original read transaction still shows the tables as uninitialized (since the data
	// available to it is still incomplete).
	require.NotEmpty(t, p.FrontendTable.PendingInitializers(firstTxn), "expected frontends to be uninitialized")
	require.NotEmpty(t, p.BackendTable.PendingInitializers(firstTxn), "expected backends to be uninitialized")
	require.NotEmpty(t, p.ServiceTable.PendingInitializers(firstTxn), "expected services to be uninitialized")
}
