// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"
	"encoding/binary"
	"iter"
	"log/slog"
	"os"
	"slices"
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
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"

	"k8s.io/utils/ptr"
)

type testParams struct {
	cell.In

	DB     *statedb.DB
	Writer *Writer

	ServiceTable  statedb.Table[*loadbalancer.Service]
	FrontendTable statedb.Table[*loadbalancer.Frontend]
	BackendTable  statedb.Table[*loadbalancer.Backend]
}

func fixture(t testing.TB, hooks ...ServiceHook) (p testParams) {
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

	type hooksOut struct {
		cell.Out
		Hooks []ServiceHook `group:"service-hooks,flatten"`
	}
	h := hive.New(
		cell.Config(loadbalancer.DefaultConfig),
		node.LocalNodeStoreCell,
		Cell,
		cell.Provide(
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
		),
		cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
		cell.Invoke(func(p_ testParams) { p = p_ }),

		cell.Provide(
			func() hooksOut { return hooksOut{Hooks: hooks} },
		),
	)

	hive.AddConfigOverride(h, func(cfg *loadbalancer.Config) {
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
	serviceUpserts := []*loadbalancer.Service{}
	hookSentinel := uint16(123)

	p := fixture(t, func(txn statedb.ReadTxn, svc *loadbalancer.Service) {
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

		svc := &loadbalancer.Service{
			Name:   name,
			Source: source.Kubernetes,
		}
		err := p.Writer.UpsertServiceAndFrontends(
			wtxn,
			svc,
			loadbalancer.FrontendParams{
				ServiceName: name,
				Address:     frontend,
				Type:        loadbalancer.SVCTypeClusterIP,
				ServicePort: frontend.Port,
			},
		)
		require.NoError(t, err, "UpsertServiceAndFrontends")

		// Check that the hook gets called.
		require.Len(t, serviceUpserts, 1, "service hook not called")
		require.Equal(t, svc, serviceUpserts[0], "service hook called with wrong object")

		// Updating the service object with UpsertService also results in another hook call.
		origSVC := svc
		svc = &loadbalancer.Service{
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

		svc, _, found := p.ServiceTable.Get(txn, loadbalancer.ServiceByName(name))
		if assert.True(t, found, "Service not found by name") {
			assert.NotNil(t, svc)
			assert.Equal(t, name, svc.Name, "Service name not equal")
		}

		fe, _, found := p.FrontendTable.Get(txn, loadbalancer.FrontendByAddress(frontend))
		if assert.True(t, found, "Frontend not found by addr") {
			assert.NotNil(t, fe)
			assert.Equal(t, name, fe.ServiceName, "Service name not equal")
			assert.Equal(t, reconciler.StatusKindPending, fe.Status.Kind, "Expected pending status")
		}
		fe, _, found = p.FrontendTable.Get(txn, loadbalancer.FrontendByServiceName(name))
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

		_, _, found := p.ServiceTable.Get(wtxn, loadbalancer.ServiceByName(name))
		assert.False(t, found, "Service found after delete")

		_, _, found = p.FrontendTable.Get(wtxn, loadbalancer.FrontendByServiceName(name))
		assert.False(t, found, "Frontend found after delete")

		wtxn.Abort()
	}

	// Deletion by source
	{
		wtxn := p.Writer.WriteTxn()
		require.Equal(t, 1, p.ServiceTable.NumObjects(wtxn))
		err := p.Writer.DeleteServicesBySource(wtxn, source.Kubernetes)
		require.NoError(t, err, "DeleteServicesBySource failed")

		_, _, found := p.ServiceTable.Get(wtxn, loadbalancer.ServiceByName(name))
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
			&loadbalancer.Service{
				Name:   name1,
				Source: source.Kubernetes,
			},
			loadbalancer.FrontendParams{
				Address:     frontend,
				Type:        loadbalancer.SVCTypeClusterIP,
				ServicePort: frontend.Port,
			})

		require.NoError(t, err, "UpsertService failed")
		wtxn.Commit()
	}

	// UpsertBackends
	beAddr1, beAddr2, beAddr3 := mkAddr(4000), mkAddr(5000), mkAddr(6000)
	{
		wtxn := p.Writer.WriteTxn()

		// Add two backends for [name1].
		p.Writer.UpsertBackends(
			wtxn,
			name1,
			source.Kubernetes,
			loadbalancer.BackendParams{
				Address: beAddr1,
				State:   loadbalancer.BackendStateActive,
			},
			loadbalancer.BackendParams{
				Address: beAddr2,
				State:   loadbalancer.BackendStateActive,
			},
		)

		// Add a backend for the non-existing [name2].
		p.Writer.UpsertBackends(
			wtxn,
			name2,
			source.Kubernetes,
			loadbalancer.BackendParams{
				Address: beAddr3,
				State:   loadbalancer.BackendStateActive,
			},
		)

		wtxn.Commit()
	}

	// Lookup
	{
		txn := p.DB.ReadTxn()

		// By address
		for _, addr := range []loadbalancer.L3n4Addr{beAddr1, beAddr2, beAddr3} {
			be, _, found := p.BackendTable.Get(txn, loadbalancer.BackendByAddress(addr))
			if assert.True(t, found, "Backend not found with address %s", addr) {
				assert.True(t, be.Address.DeepEqual(&addr), "Backend address %s does not match %s", be.Address, addr)
			}
		}

		// By service
		bes := statedb.Collect(p.BackendTable.List(txn, loadbalancer.BackendByServiceName(name1)))
		require.Len(t, bes, 2)
		require.True(t, bes[0].Address.DeepEqual(&beAddr1))
		require.True(t, bes[1].Address.DeepEqual(&beAddr2))

		// Backends for [name2] can be found even though the service doesn't exist (yet).
		bes = statedb.Collect(p.BackendTable.List(txn, loadbalancer.BackendByServiceName(name2)))
		require.Len(t, bes, 1)
		require.True(t, bes[0].Address.DeepEqual(&beAddr3))
	}

	// ReleaseBackend
	{
		wtxn := p.Writer.WriteTxn()

		// Release the [name1] reference to [beAddr1].
		require.Equal(t, 3, p.BackendTable.NumObjects(wtxn))
		err := p.Writer.ReleaseBackends(wtxn, name1, beAddr1)
		require.NoError(t, err, "ReleaseBackend failed")

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
		&loadbalancer.Service{
			Name:   name,
			Source: source.Kubernetes,
		},
		loadbalancer.FrontendParams{
			ServiceName: name,
			Address:     addr,
			Type:        loadbalancer.SVCTypeClusterIP,
			ServicePort: 12345,
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

func TestWriter_SetBackends(t *testing.T) {
	p := fixture(t)

	name1 := loadbalancer.ServiceName{Namespace: "test", Name: "test1"}
	name2 := loadbalancer.ServiceName{Namespace: "test", Name: "test2"}

	feAddr1 := loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(1231), 1231, loadbalancer.ScopeExternal)
	feAddr2 := loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(1232), 1232, loadbalancer.ScopeExternal)

	beAddr1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(121), 4241, loadbalancer.ScopeExternal)
	beAddr2 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(122), 4242, loadbalancer.ScopeExternal)
	beAddr3 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(123), 4243, loadbalancer.ScopeExternal)

	backend1 := loadbalancer.BackendParams{Address: beAddr1}
	backend2 := loadbalancer.BackendParams{Address: beAddr2}
	backend3 := loadbalancer.BackendParams{Address: beAddr3}

	backend1_cluster1 := loadbalancer.BackendParams{Address: beAddr1, ClusterID: 1}
	backend2_cluster1 := loadbalancer.BackendParams{Address: beAddr2, ClusterID: 1}
	backend3_cluster2 := loadbalancer.BackendParams{Address: beAddr3, ClusterID: 2}

	type testCase struct {
		desc   string
		action func(*testing.T, *Writer, WriteTxn)
		// In the references and existence maps below, false values should be specified explicitly
		// for the non-existence to be verified.
		references map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool
		existence  map[loadbalancer.L3n4Addr]bool
	}
	tcs := []testCase{
		{
			desc: "create two services and frontends",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				_, err := w.UpsertService(wtxn, &loadbalancer.Service{Name: name1})
				require.NoError(t, err)
				_, err = w.UpsertService(wtxn, &loadbalancer.Service{Name: name2})
				require.NoError(t, err)
				_, err = w.UpsertFrontend(wtxn, loadbalancer.FrontendParams{Address: *feAddr1, ServiceName: name1})
				require.NoError(t, err)
				_, err = w.UpsertFrontend(wtxn, loadbalancer.FrontendParams{Address: *feAddr2, ServiceName: name2})
				require.NoError(t, err)
			},
		},
		{
			desc: "add all backends to first service",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name1, source.Kubernetes, backend1, backend2, backend3))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: true, beAddr2: true, beAddr3: true},
				name2: {beAddr1: false, beAddr2: false, beAddr3: false},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: true, beAddr2: true, beAddr3: true},
		},
		{
			desc: "add all backends to second service",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name2, source.Kubernetes, backend1, backend2, backend3))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: true, beAddr2: true, beAddr3: true},
				name2: {beAddr1: true, beAddr2: true, beAddr3: true},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: true, beAddr2: true, beAddr3: true},
		},
		{
			desc: "delete third backend from first service",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name1, source.Kubernetes, backend1, backend2))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: true, beAddr2: true, beAddr3: false},
				name2: {beAddr1: true, beAddr2: true, beAddr3: true},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: true, beAddr2: true, beAddr3: true},
		},
		{
			desc: "delete first backend from both services",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name1, source.Kubernetes, backend2))
				require.NoError(t, w.SetBackends(wtxn, name2, source.Kubernetes, backend2, backend3))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: false, beAddr2: true, beAddr3: false},
				name2: {beAddr1: false, beAddr2: true, beAddr3: true},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: false, beAddr2: true, beAddr3: true},
		},
		{
			desc: "delete remaining two backends from second service",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name2, source.Kubernetes))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: false, beAddr2: true, beAddr3: false},
				name2: {beAddr1: false, beAddr2: false, beAddr3: false},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: false, beAddr2: true, beAddr3: false},
		},
		{
			desc: "delete remaining backend from first service",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name1, source.Kubernetes))
				require.NoError(t, w.SetBackends(wtxn, name2, source.Kubernetes))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: false, beAddr2: false, beAddr3: false},
				name2: {beAddr1: false, beAddr2: false, beAddr3: false},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: false, beAddr2: false, beAddr3: false},
		},
		{
			desc: "add backend from other clusters",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackendsOfCluster(wtxn, name1, source.ClusterMesh, 1, backend1_cluster1, backend2_cluster1))
				require.NoError(t, w.SetBackendsOfCluster(wtxn, name1, source.ClusterMesh, 2, backend3_cluster2))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: true, beAddr2: true, beAddr3: true},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: true, beAddr2: true, beAddr3: true},
		},
		{
			desc: "delete backend2 from first cluster",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackendsOfCluster(wtxn, name1, source.ClusterMesh, 1, backend1_cluster1))
				require.NoError(t, w.SetBackendsOfCluster(wtxn, name1, source.ClusterMesh, 2, backend3_cluster2))
			},
			references: map[loadbalancer.ServiceName]map[loadbalancer.L3n4Addr]bool{
				name1: {beAddr1: true, beAddr2: false, beAddr3: true},
			},
			existence: map[loadbalancer.L3n4Addr]bool{beAddr1: true, beAddr2: false, beAddr3: true},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			wtxn := p.Writer.WriteTxn()
			tc.action(t, p.Writer, wtxn)
			txn := wtxn.Commit()
			for name, innerMap := range tc.references {
				for addr, present := range innerMap {
					fe, _, ok := p.Writer.Frontends().Get(txn, loadbalancer.FrontendByServiceName(name)) // We assume only one frontend per service
					require.True(t, ok)
					if !present {
						be, _, found := p.Writer.Backends().Get(txn, loadbalancer.BackendByAddress(addr))
						if found { // Backend should not exist...
							ptr := be.GetInstance(name)
							require.Nil(t, ptr) // ...or not be associated with the service.
						}
						for be := range fe.Backends {
							require.NotEqual(t, addr, be.Address)
						}
					} else {
						be, _, found := p.Writer.Backends().Get(txn, loadbalancer.BackendByAddress(addr))
						require.True(t, found)
						ptr := be.GetInstance(name)
						require.NotNil(t, ptr)
						foundInFrontend := false
						for be := range fe.Backends {
							foundInFrontend = foundInFrontend || be.Address == addr
						}
						require.True(t, foundInFrontend)
					}
				}
			}
			for addr, shouldExist := range tc.existence {
				_, _, found := p.Writer.Backends().Get(txn, loadbalancer.BackendByAddress(addr))
				require.Equal(t, shouldExist, found, "address: %s", addr.String())
			}
		})
	}
}

func TestWriter_WithConflictingSources(t *testing.T) {
	p := fixture(t)

	name1 := loadbalancer.ServiceName{Namespace: "test", Name: "test1"}
	name2 := loadbalancer.ServiceName{Namespace: "test", Name: "test2"}

	feAddr1 := loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(1234), 1234, loadbalancer.ScopeExternal)
	feAddr2 := loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(1235), 1235, loadbalancer.ScopeExternal)

	backendTemplate := loadbalancer.BackendParams{Address: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(123), 4242, loadbalancer.ScopeExternal)}
	backend10 := backendTemplate
	backend10.Weight = 10
	backend11 := backendTemplate
	backend11.Weight = 11
	backend12 := backendTemplate
	backend12.Weight = 12
	backend20 := backendTemplate
	backend20.Weight = 20

	type weight = uint16
	type testCase struct {
		desc   string
		action func(*testing.T, *Writer, WriteTxn)
		// want specifies the weight of the single tested backend for a given service.
		// Use nil to indicate that instance for a given service should not exist.
		want map[loadbalancer.ServiceName]*weight
	}

	tcs := []testCase{
		{
			desc: "create services and frontends",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				_, err := w.UpsertService(wtxn, &loadbalancer.Service{Name: name1})
				require.NoError(t, err)
				_, err = w.UpsertService(wtxn, &loadbalancer.Service{Name: name2})
				require.NoError(t, err)
				_, err = w.UpsertFrontend(wtxn, loadbalancer.FrontendParams{Address: *feAddr1, ServiceName: name1})
				require.NoError(t, err)
				_, err = w.UpsertFrontend(wtxn, loadbalancer.FrontendParams{Address: *feAddr2, ServiceName: name2})
				require.NoError(t, err)
			},
			want: map[loadbalancer.ServiceName]*weight{name1: nil, name2: nil},
		},
		{
			desc: "add backends for two services",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.UpsertBackends(wtxn, name1, source.Kubernetes, backend10))
				require.NoError(t, w.UpsertBackends(wtxn, name2, source.KubeAPIServer, backend20))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](10), name2: ptr.To[weight](20)},
		},
		{
			desc: "update backend from higher priority source",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.UpsertBackends(wtxn, name1, source.KubeAPIServer, backend11))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](11), name2: ptr.To[weight](20)},
		},
		{
			desc: "update backend from lower priority source",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.UpsertBackends(wtxn, name1, source.Kubernetes, backend12))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](11), name2: ptr.To[weight](20)}, // no change here
		},
		{
			desc: "delete backends",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.DeleteBackendsOfService(wtxn, name1, source.KubeAPIServer))
				require.NoError(t, w.DeleteBackendsOfService(wtxn, name2, source.KubeAPIServer))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](12), name2: nil}, // change from the previous case surfaces now
		},
		{
			desc: "add deleted backends back",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.UpsertBackends(wtxn, name1, source.KubeAPIServer, backend11))
				require.NoError(t, w.UpsertBackends(wtxn, name2, source.KubeAPIServer, backend20))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](11), name2: ptr.To[weight](20)},
		},
		{
			desc: "delete via SetBackends",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name1, source.KubeAPIServer))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](12), name2: ptr.To[weight](20)},
		},
		{
			desc: "add it back via SetBackends",
			action: func(t *testing.T, w *Writer, wtxn WriteTxn) {
				require.NoError(t, w.SetBackends(wtxn, name1, source.KubeAPIServer, backend11))
			},
			want: map[loadbalancer.ServiceName]*weight{name1: ptr.To[weight](11), name2: ptr.To[weight](20)},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			wtxn := p.Writer.WriteTxn()
			tc.action(t, p.Writer, wtxn)
			txn := wtxn.Commit()
			for name, weight := range tc.want {
				fe, _, ok := p.Writer.Frontends().Get(txn, loadbalancer.FrontendByServiceName(name)) // We assume only one frontend per service
				require.True(t, ok)
				if weight == nil {
					_, _, found := p.Writer.Backends().Get(txn, loadbalancer.BackendByServiceName(name))
					require.False(t, found)
					require.Empty(t, statedb.Collect(iter.Seq2[loadbalancer.BackendParams, statedb.Revision](fe.Backends)))
				} else {
					backends := p.Writer.Backends().List(txn, loadbalancer.BackendByServiceName(name))
					count := 0
					var backendFromTable *loadbalancer.Backend
					for b := range backends {
						count++
						backendFromTable = b
					}
					require.Equal(t, 1, count)
					actual := slices.Collect(statedb.ToSeq(iter.Seq2[loadbalancer.BackendParams, statedb.Revision](fe.Backends)))
					require.Len(t, actual, 1)
					for desc, b := range map[string]loadbalancer.BackendParams{"from table": *backendFromTable.GetInstance(name), "from Frontend": actual[0]} {
						require.NotNil(t, b, desc)
						require.Equal(t, int(*weight), int(b.Weight), "backend %s", desc)
					}
				}
			}
		})
	}
}

func TestWriter_SetSelectBackends(t *testing.T) {
	p := fixture(t)
	w := p.Writer

	var feAddr loadbalancer.L3n4Addr
	feAddr.ParseFromString("1.0.0.1:80/TCP")
	svcName := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}

	var beAddr loadbalancer.L3n4Addr
	beAddr.ParseFromString("2.0.0.1:80/TCP")

	w.SetSelectBackendsFunc(func(bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, fe *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
		require.NotNil(t, bes)
		require.NotNil(t, svc)
		require.NotNil(t, fe)
		require.Equal(t, feAddr.String(), fe.Address.String())
		return func(yield func(loadbalancer.BackendParams, uint64) bool) {
			yield(loadbalancer.BackendParams{
				Address: beAddr,
				Source:  "test",
			}, 1)
		}
	})

	wtxn := w.WriteTxn()
	err := w.UpsertServiceAndFrontends(wtxn,
		&loadbalancer.Service{Name: svcName},
		loadbalancer.FrontendParams{Address: feAddr, ServiceName: loadbalancer.ServiceName{Namespace: "test", Name: "test"}})
	require.NoError(t, err, "UpsertServiceAndFrontends")
	txn := wtxn.Commit()

	fe, _, found := w.Frontends().Get(txn, loadbalancer.FrontendByAddress(feAddr))
	require.True(t, found)
	bes := slices.Collect(statedb.ToSeq(iter.Seq2[loadbalancer.BackendParams, statedb.Revision](fe.Backends)))
	require.Len(t, bes, 1)
	require.Equal(t, beAddr.String(), bes[0].Address.String())
}
