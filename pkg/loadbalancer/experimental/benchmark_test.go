// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/source"
)

// Benchmark_UpsertServiceAndFrontends_100 tests the best-case upsert performance
// where many services and frontends are inserted in a single transaction. This
// reduces allocations a lot as the inner radix tree nodes allocated in the transaction
// can be reused in subsequent inserts.
func Benchmark_UpsertServiceAndFrontends_100(b *testing.B) {
	benchmark_UpsertServiceAndFrontends(b, 100)
}

// Benchmark_UpsertServiceAndFrontends_1 tests the worst-case upsert performance.
// With a single service and frontend inserted per transaction causes many more
// radix tree nodes to be allocated since they cannot be reused.
func Benchmark_UpsertServiceAndFrontends_1(b *testing.B) {
	benchmark_UpsertServiceAndFrontends(b, 1)
}

func benchmark_UpsertServiceAndFrontends(b *testing.B, numObjects int) {
	p := fixture(b)

	// Add 1000 existing objects to the table. This makes the benchmark more
	// realistic as we'll then have existing objects in the table which makes the
	// inserts slightly more costly.
	wtxn := p.Writer.WriteTxn()
	for i := 0; i < 1000; i++ {
		name := loadbalancer.ServiceName{Namespace: "test-existing", Name: fmt.Sprintf("svc-%d", i)}
		var addr1 [4]byte
		binary.BigEndian.PutUint32(addr1[:], 0x02000000+uint32(i))
		addrCluster, _ := types.AddrClusterFromIP(addr1[:])
		p.Writer.UpsertServiceAndFrontends(
			wtxn,
			&experimental.Service{
				Name:   name,
				Source: source.Kubernetes,
			},
			&experimental.Frontend{
				Address:  *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal),
				Type:     loadbalancer.SVCTypeClusterIP,
				PortName: "foo",
				ID:       0,
			},
		)
	}
	wtxn.Commit()

	b.ResetTimer()

	// Benchmark the speed at which a new service is upserted. 'numObjects' are inserted in one
	// WriteTxn.
	for n := 0; n < b.N; n++ {
		wtxn := p.Writer.WriteTxn()
		for i := 0; i < numObjects; i++ {
			name := loadbalancer.ServiceName{Namespace: "test-new", Name: fmt.Sprintf("svc-%d", i)}
			var addr1 [4]byte
			binary.BigEndian.PutUint32(addr1[:], 0x01000000+uint32(i))
			addrCluster, _ := types.AddrClusterFromIP(addr1[:])
			p.Writer.UpsertServiceAndFrontends(
				wtxn,
				&experimental.Service{
					Name:   name,
					Source: source.Kubernetes,
				},
				&experimental.Frontend{
					Address:  *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal),
					Type:     loadbalancer.SVCTypeClusterIP,
					PortName: "",
					ID:       0,
				},
			)
		}
		wtxn.Abort()
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*numObjects)/b.Elapsed().Seconds(), "objects/sec")
}

func BenchmarkInsertBackend(b *testing.B) {
	p := fixture(b)

	addrCluster1 := types.MustParseAddrCluster("1.0.0.1")
	addrCluster2 := types.MustParseAddrCluster("2.0.0.2")

	name := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}
	wtxn := p.Writer.WriteTxn()

	p.Writer.UpsertServiceAndFrontends(
		wtxn,
		&experimental.Service{
			Name:   name,
			Source: source.Kubernetes,
		},
		&experimental.Frontend{
			Address:  *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
			Type:     loadbalancer.SVCTypeClusterIP,
			PortName: "",
			ID:       0,
		},
	)
	wtxn.Commit()

	numObjects := 1000

	// Add 'numObjects' existing objects to the table.
	wtxn = p.Writer.WriteTxn()
	for i := 0; i < numObjects; i++ {
		beAddr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, uint16(i), loadbalancer.ScopeExternal)
		p.Writer.UpsertBackends(
			wtxn,
			name,
			source.Kubernetes,
			&loadbalancer.Backend{
				L3n4Addr: beAddr,
				State:    loadbalancer.BackendStateActive,
			},
		)
	}
	wtxn.Commit()

	b.ResetTimer()

	// Benchmark the speed at which a new backend is upserted. 'numObjects' are inserted in one
	// WriteTxn to amortize the cost of WriteTxn&Commit.
	for n := 0; n < b.N; n++ {
		wtxn = p.Writer.WriteTxn()
		for i := 0; i < numObjects; i++ {
			beAddr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, uint16(i), loadbalancer.ScopeExternal)
			p.Writer.UpsertBackends(
				wtxn,
				name,
				source.Kubernetes,
				&loadbalancer.Backend{
					L3n4Addr: beAddr,
					State:    loadbalancer.BackendStateActive,
				},
			)
		}
		// Don't commit the changes so we actually test the cost of Insert() of new object.
		wtxn.Abort()
	}

	b.StopTimer()
	b.ReportMetric(float64(b.N*numObjects)/b.Elapsed().Seconds(), "objects/sec")
}
func BenchmarkReplaceBackend(b *testing.B) {
	p := fixture(b)

	addrCluster1 := types.MustParseAddrCluster("1.0.0.1")
	addrCluster2 := types.MustParseAddrCluster("2.0.0.2")

	name := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}
	wtxn := p.Writer.WriteTxn()

	p.Writer.UpsertServiceAndFrontends(
		wtxn,
		&experimental.Service{
			Name:   name,
			Source: source.Kubernetes,
		},
		&experimental.Frontend{
			Address:  *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 12345, loadbalancer.ScopeExternal),
			Type:     loadbalancer.SVCTypeClusterIP,
			PortName: "",
			ID:       0,
		},
	)

	beAddr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, uint16(1234), loadbalancer.ScopeExternal)
	p.Writer.UpsertBackends(
		wtxn,
		name,
		source.Kubernetes,
		&loadbalancer.Backend{
			L3n4Addr: beAddr,
			State:    loadbalancer.BackendStateActive,
		},
	)
	wtxn.Commit()

	b.ResetTimer()
	wtxn = p.Writer.WriteTxn()
	for i := 0; i < b.N; i++ {
		p.Writer.UpsertBackends(
			wtxn,
			name,
			source.Kubernetes,
			&loadbalancer.Backend{
				L3n4Addr: beAddr,
				State:    loadbalancer.BackendStateActive,
			},
		)
	}
	wtxn.Abort()

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")
}

func BenchmarkReplaceService(b *testing.B) {
	p := fixture(b)

	addrCluster := types.MustParseAddrCluster("1.0.0.1")
	l3n4Addr := *loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster, 12345, loadbalancer.ScopeExternal)

	name := loadbalancer.ServiceName{Namespace: "test", Name: "svc"}
	wtxn := p.Writer.WriteTxn()

	p.Writer.UpsertServiceAndFrontends(
		wtxn,
		&experimental.Service{
			Name:   name,
			Source: source.Kubernetes,
		},
		&experimental.Frontend{
			Address:  l3n4Addr,
			Type:     loadbalancer.SVCTypeClusterIP,
			PortName: "",
			ID:       0,
		},
	)

	wtxn.Commit()

	b.ResetTimer()

	// Replace the service b.N times
	wtxn = p.Writer.WriteTxn()
	for i := 0; i < b.N; i++ {
		p.Writer.UpsertServiceAndFrontends(
			wtxn,
			&experimental.Service{
				Name:   name,
				Source: source.Kubernetes,
			},
			&experimental.Frontend{
				Address:  l3n4Addr,
				Type:     loadbalancer.SVCTypeClusterIP,
				PortName: "",
				ID:       0,
			},
		)
	}
	wtxn.Abort()

	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "objects/sec")
}
