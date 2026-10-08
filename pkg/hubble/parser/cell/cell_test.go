// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestPayloadGetters_GetServiceByAddr(t *testing.T) {
	db := statedb.New()
	fes, err := loadbalancer.NewFrontendsTable(loadbalancer.DefaultConfig, db)
	require.NoError(t, err)

	var addrTCP, addrUDP loadbalancer.L3n4Addr
	require.NoError(t, addrTCP.ParseFromString("10.0.0.1:80/TCP"))
	require.NoError(t, addrUDP.ParseFromString("20.0.0.2:80/UDP"))
	wtxn := db.WriteTxn(fes)
	svcNameTCP := loadbalancer.NewServiceName("nstcp", "tcp")
	svcNameUDP := loadbalancer.NewServiceName("nsudp", "udp")
	fes.Insert(wtxn, &loadbalancer.Frontend{FrontendParams: loadbalancer.FrontendParams{Address: addrTCP, ServiceName: svcNameTCP}})
	fes.Insert(wtxn, &loadbalancer.Frontend{FrontendParams: loadbalancer.FrontendParams{Address: addrUDP, ServiceName: svcNameUDP}})
	wtxn.Commit()

	pg := payloadGetters{db: db, frontends: fes}

	svc := pg.GetServiceByAddr(addrTCP.Addr(), 80)
	require.NotNil(t, svc)
	require.Equal(t, svcNameTCP.Namespace(), svc.Namespace)
	require.Equal(t, svcNameTCP.Name(), svc.Name)

	svc = pg.GetServiceByAddr(addrUDP.Addr(), 80)
	require.NotNil(t, svc)
	require.Equal(t, svcNameUDP.Namespace(), svc.Namespace)
	require.Equal(t, svcNameUDP.Name(), svc.Name)

	svc = pg.GetServiceByAddr(addrUDP.Addr(), 81)
	require.Nil(t, svc)
}

func BenchmarkGetServiceByAddr(b *testing.B) {
	db := statedb.New()
	fes, err := loadbalancer.NewFrontendsTable(loadbalancer.DefaultConfig, db)
	require.NoError(b, err)
	pg := payloadGetters{db: db, frontends: fes}

	b.ResetTimer()
	for b.Loop() {
		addr, port := randomAddrPort()
		svc := pg.GetServiceByAddr(addr, port)
		if svc != nil {
			b.Fatal("non-nil svc")
		}
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	b.ReportMetric(float64(mem.HeapSys+mem.HeapReleased)/1024/1024, "HeapSys+Released/MB")
}

func randomAddrPort() (netip.Addr, uint16) {
	addr := [4]byte{byte(rand.Int()), byte(rand.Int()), byte(rand.Int()), byte(rand.Int())}
	return netip.AddrFrom4(addr), uint16(rand.Int())
}
