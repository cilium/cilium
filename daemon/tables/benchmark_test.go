package tables

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func BenchmarkUpsertService(b *testing.B) {
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

	wtxn := p.Services.WriteTxn()
	for i := 0; i < b.N; i++ {
		name := loadbalancer.ServiceName{Namespace: "test", Name: fmt.Sprintf("svc-%d", i)}
		var addr1 [4]byte
		binary.BigEndian.PutUint32(addr1[:], 0x01000000+uint32(i))
		addrCluster1, _ := types.AddrClusterFromIP(addr1[:])
		p.Services.UpsertService(
			wtxn,
			name,
			ServiceParams{
				L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
				Type:     loadbalancer.SVCTypeClusterIP,
				Labels:   nil,
				Source:   source.Kubernetes,
			},
		)
	}
	wtxn.Commit()

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}

func BenchmarkUpsertBackend(b *testing.B) {
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
		ServiceParams{
			L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
			Type:     loadbalancer.SVCTypeClusterIP,
			Labels:   nil,
			Source:   source.Kubernetes,
		},
	)
	wtxn.Commit()

	/*beAddr1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 1000, loadbalancer.ScopeExternal)
	beAddr2 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 1001, loadbalancer.ScopeExternal)
	beAddr3 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 1002, loadbalancer.ScopeExternal)*/
	wtxn = p.Services.WriteTxn()
	for i := 0; i < b.N; i++ {
		beAddr1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, uint16(i), loadbalancer.ScopeExternal)
		p.Services.UpsertBackends(
			wtxn,
			"test",
			name,
			BackendParams{
				L3n4Addr: beAddr1,
				Source:   source.Kubernetes,
				State:    loadbalancer.BackendStateActive,
			},
			/*BackendParams{
				L3n4Addr: beAddr2,
				Source:   source.Kubernetes,
				State:    loadbalancer.BackendStateActive,
			},
			BackendParams{
				L3n4Addr: beAddr3,
				Source:   source.Kubernetes,
				State:    loadbalancer.BackendStateActive,
			},*/
		)
	}
	wtxn.Commit()

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
		ServicesCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	b.ResetTimer()

	batchSize := 100

	for i := 0; i < b.N; i += batchSize {
		wtxn := p.Services.WriteTxn()
		for j := 0; j < batchSize; j++ {
			name := loadbalancer.ServiceName{Namespace: "test", Name: fmt.Sprintf("svc-%d", i+j)}
			var addr1 [4]byte
			binary.BigEndian.PutUint32(addr1[:], 0x01000000+uint32(i+j))
			addrCluster1, _ := types.AddrClusterFromIP(addr1[:])
			p.Services.UpsertService(
				wtxn,
				name,
				ServiceParams{
					L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
					Type:     loadbalancer.SVCTypeClusterIP,
					Labels:   nil,
					Source:   source.Kubernetes,
				},
			)

			var addr2 [4]byte
			binary.BigEndian.PutUint32(addr2[:], 0x02000000+uint32(i+j))
			addrCluster2, _ := types.AddrClusterFromIP(addr2[:])
			p.Services.UpsertBackends(
				wtxn,
				name.Name,
				name,
				BackendParams{
					L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 12345, loadbalancer.ScopeExternal),
					Source:   source.Kubernetes,
					State:    loadbalancer.BackendStateActive,
				},
			)
		}
		wtxn.Commit()
	}

	// Wait until all services have been reconciled.
	reconciler.WaitForReconciliation(
		context.TODO(),
		p.DB,
		p.ServiceTable,
		ServiceStatusIndex,
	)

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))

}

func BenchmarkInsertBackend(b *testing.B) {
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
		ServiceParams{
			L3n4Addr: *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
			Type:     loadbalancer.SVCTypeClusterIP,
			Labels:   nil,
			Source:   source.Kubernetes,
		},
	)
	wtxn.Commit()

	refs := container.NewImmSetFunc(loadbalancer.ServiceName.Compare, name)

	/*beAddr1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 1000, loadbalancer.ScopeExternal)
	beAddr2 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 1001, loadbalancer.ScopeExternal)
	beAddr3 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 1002, loadbalancer.ScopeExternal)*/
	beAddr1 := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, uint16(0), loadbalancer.ScopeExternal)
	for i := 0; i < b.N; i++ {
		wtxn = p.Services.WriteTxn()
		addr := beAddr1
		addr.Port = uint16(i)
		p.BackendTable.(statedb.RWTable[*Backend]).Insert(
			wtxn,
			&Backend{
				BackendParams: BackendParams{
					L3n4Addr: addr,
					Source:   source.Kubernetes,
					State:    loadbalancer.BackendStateActive,
				},
				ReferencedBy: refs,
			},
		)
		wtxn.Commit()
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")

	require.NoError(b, h.Stop(context.TODO()))
}
