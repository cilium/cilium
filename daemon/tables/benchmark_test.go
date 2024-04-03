package tables

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func BenchmarkInsertService(b *testing.B) {
	type params struct {
		cell.In

		DB       *statedb.DB
		Services *Services

		ServiceTable statedb.Table[*Service]
	}

	var p params

	logging.SetLogLevel(logrus.ErrorLevel)

	h := hive.New(
		job.Cell,
		statedb.Cell,
		reconciler.Cell,
		ServicesCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	b.ResetTimer()

	numObjects := 100

	// Add 'numObjects' existing objects to the table.
	wtxn := p.Services.WriteTxn()
	for i := 0; i < numObjects; i++ {
		name := loadbalancer.ServiceName{Namespace: "test-existing", Name: fmt.Sprintf("svc-%d", i)}
		var addr1 [4]byte
		binary.BigEndian.PutUint32(addr1[:], 0x02000000+uint32(i))
		addrCluster, _ := types.AddrClusterFromIP(addr1[:])
		p.Services.UpsertService(
			wtxn,
			name,
			&ServiceParams{
				L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal),
				Type:     loadbalancer.SVCTypeClusterIP,
				Labels:   nil,
				Source:   source.Kubernetes,
			},
		)
	}
	wtxn.Commit()

	// Benchmark the speed at which a new service is upserted. 'numObjects' are inserted in one
	// WriteTxn to amortize the cost of WriteTxn&Commit.
	for n := 0; n < b.N; n++ {
		wtxn := p.Services.WriteTxn()
		for i := 0; i < numObjects; i++ {
			name := loadbalancer.ServiceName{Namespace: "test-new", Name: fmt.Sprintf("svc-%d", i)}
			var addr1 [4]byte
			binary.BigEndian.PutUint32(addr1[:], 0x01000000+uint32(i))
			addrCluster, _ := types.AddrClusterFromIP(addr1[:])
			p.Services.UpsertService(
				wtxn,
				name,
				&ServiceParams{
					L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal),
					Type:     loadbalancer.SVCTypeClusterIP,
					Labels:   nil,
					Source:   source.Kubernetes,
				},
			)
		}
		wtxn.Abort()
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*numObjects)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}

func BenchmarkInsertBackend(b *testing.B) {
	type params struct {
		cell.In

		DB       *statedb.DB
		Services *Services

		ServiceTable statedb.Table[*Service]
	}

	var p params

	logging.SetLogLevel(logrus.ErrorLevel)

	h := hive.New(
		job.Cell,
		statedb.Cell,
		reconciler.Cell,
		ServicesCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	b.ResetTimer()

	addrCluster1 := types.MustParseAddrCluster("1.0.0.1")
	addrCluster2 := types.MustParseAddrCluster("2.0.0.2")

	name := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}
	wtxn := p.Services.WriteTxn()
	p.Services.UpsertService(
		wtxn,
		name,
		&ServiceParams{
			L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
			Type:     loadbalancer.SVCTypeClusterIP,
			Labels:   nil,
			Source:   source.Kubernetes,
		},
	)
	wtxn.Commit()

	numObjects := 1000

	// Add 'numObjects' existing objects to the table.
	wtxn = p.Services.WriteTxn()
	for i := 0; i < numObjects; i++ {
		beAddr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, uint16(i), loadbalancer.ScopeExternal)
		p.Services.UpsertBackends(
			wtxn,
			name,
			BackendParams{
				Source: source.Kubernetes,
				Backend: loadbalancer.Backend{
					L3n4Addr: beAddr,
					State:    loadbalancer.BackendStateActive,
				},
			},
		)
	}
	wtxn.Abort()

	// Benchmark the speed at which a new backend is upserted. 'numObjects' are inserted in one
	// WriteTxn to amortize the cost of WriteTxn&Commit.
	for n := 0; n < b.N; n++ {
		wtxn = p.Services.WriteTxn()
		for i := 0; i < numObjects; i++ {
			beAddr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, uint16(i), loadbalancer.ScopeExternal)
			p.Services.UpsertBackends(
				wtxn,
				name,
				BackendParams{
					Source: source.Kubernetes,
					Backend: loadbalancer.Backend{
						L3n4Addr: beAddr,
						State:    loadbalancer.BackendStateActive,
					},
				},
			)
		}
		// Don't commit the changes so we actually test the cost of Insert() of new object.
		wtxn.Abort()
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*numObjects)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}
func BenchmarkReplaceBackend(b *testing.B) {
	type params struct {
		cell.In

		DB       *statedb.DB
		Services *Services

		ServiceTable statedb.Table[*Service]
		BackendTable statedb.Table[*Backend]
	}

	var p params

	logging.SetLogLevel(logrus.ErrorLevel)

	h := hive.New(
		job.Cell,
		statedb.Cell,
		reconciler.Cell,
		ServicesCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	b.ResetTimer()

	addrCluster1 := types.MustParseAddrCluster("1.0.0.1")
	addrCluster2 := types.MustParseAddrCluster("2.0.0.2")

	name := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}
	wtxn := p.Services.WriteTxn()
	p.Services.UpsertService(
		wtxn,
		name,
		&ServiceParams{
			L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
			Type:     loadbalancer.SVCTypeClusterIP,
			Labels:   nil,
			Source:   source.Kubernetes,
		},
	)

	beAddr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, uint16(1234), loadbalancer.ScopeExternal)
	p.Services.UpsertBackends(
		wtxn,
		name,
		BackendParams{
			Source: source.Kubernetes,
			Backend: loadbalancer.Backend{
				L3n4Addr: beAddr,
				State:    loadbalancer.BackendStateActive,
			},
		},
	)
	wtxn.Commit()

	wtxn = p.Services.WriteTxn()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Services.UpsertBackends(
			wtxn,
			name,
			BackendParams{
				Source: source.Kubernetes,
				Backend: loadbalancer.Backend{
					L3n4Addr: beAddr,
					State:    loadbalancer.BackendStateActive,
				},
			},
		)
	}
	wtxn.Abort()

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}

func BenchmarkReplaceService(b *testing.B) {
	type params struct {
		cell.In

		DB       *statedb.DB
		Services *Services

		ServiceTable statedb.Table[*Service]
		BackendTable statedb.Table[*Backend]
	}

	var p params

	logging.SetLogLevel(logrus.ErrorLevel)

	h := hive.New(
		job.Cell,
		statedb.Cell,
		reconciler.Cell,
		ServicesCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	b.ResetTimer()

	addrCluster := types.MustParseAddrCluster("1.0.0.1")
	l3n4Addr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal)

	name := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}
	wtxn := p.Services.WriteTxn()
	p.Services.UpsertService(
		wtxn,
		name,
		&ServiceParams{
			L3n4Addr: l3n4Addr,
			Type:     loadbalancer.SVCTypeClusterIP,
			Labels:   nil,
			Source:   source.Kubernetes,
		},
	)
	wtxn.Commit()

	b.ResetTimer()

	// Replace the service b.N times
	wtxn = p.Services.WriteTxn()
	for i := 0; i < b.N; i++ {
		p.Services.UpsertService(
			wtxn,
			name,
			&ServiceParams{
				L3n4Addr: l3n4Addr,
				Type:     loadbalancer.SVCTypeClusterIP,
				Labels:   nil,
				Source:   source.Kubernetes,
			},
		)
	}
	wtxn.Abort()

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}

func BenchmarkControlPlane(b *testing.B) {
	type params struct {
		cell.In

		DB       *statedb.DB
		Services *Services

		ServiceTable statedb.Table[*Service]
	}

	var p params

	logging.SetLogLevel(logrus.ErrorLevel)

	h := hive.New(
		job.Cell,
		statedb.Cell,
		reconciler.Cell,
		ServicesReconcilerCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	b.ResetTimer()

	numObjects := 1000

	var lastName loadbalancer.ServiceName
	for n := 0; n < b.N; n++ {
		wtxn := p.Services.WriteTxn()
		for i := 0; i < numObjects; i++ {
			name := loadbalancer.ServiceName{Namespace: "test", Name: fmt.Sprintf("svc-%d", i)}
			lastName = name
			var addr1 [4]byte
			binary.BigEndian.PutUint32(addr1[:], 0x01000000+uint32(i))
			addrCluster1, _ := types.AddrClusterFromIP(addr1[:])
			p.Services.UpsertService(
				wtxn,
				name,
				&ServiceParams{
					L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
					Type:     loadbalancer.SVCTypeClusterIP,
					Labels:   nil,
					Source:   source.Kubernetes,
				},
			)

			var addr2 [4]byte
			binary.BigEndian.PutUint32(addr2[:], 0x02000000+uint32(i))
			addrCluster2, _ := types.AddrClusterFromIP(addr2[:])
			p.Services.UpsertBackends(
				wtxn,
				name,
				BackendParams{
					Source: source.Kubernetes,
					Backend: loadbalancer.Backend{
						L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 12345, loadbalancer.ScopeExternal),
						State:    loadbalancer.BackendStateActive,
					},
				},
			)
		}
		wtxn.Commit()

		for {
			svc, _, watch, ok := p.ServiceTable.FirstWatch(p.DB.ReadTxn(), ServiceNameIndex.Query(lastName))
			if !ok {
				b.Fatalf("%s not found", lastName)
			}
			if svc.BPFStatus.Kind == reconciler.StatusKindDone {
				break
			}
			<-watch
		}
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*numObjects)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}
