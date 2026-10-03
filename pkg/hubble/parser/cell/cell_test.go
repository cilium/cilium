// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// fakeEndpointManager only implements LookupCiliumID, any other method panics.
type fakeEndpointManager struct {
	endpointmanager.EndpointManager
	endpoints map[uint16]*endpoint.Endpoint
}

func (f *fakeEndpointManager) LookupCiliumID(id uint16) *endpoint.Endpoint {
	return f.endpoints[id]
}

func TestPayloadGetters_GetNamesOf(t *testing.T) {
	const epID = 42
	now := time.Now()
	ip := netip.MustParseAddr("1.1.1.1")

	ep := &endpoint.Endpoint{
		DNSHistory: fqdn.NewDNSCache(0),
		DNSZombies: fqdn.NewDNSZombieMappings(hivetest.Logger(t), 100, 100),
	}
	pg := payloadGetters{endpointManager: &fakeEndpointManager{
		endpoints: map[uint16]*endpoint.Endpoint{epID: ep},
	}}

	// Names in DNSHistory are current: they are reported by GetNamesOf only.
	ep.DNSHistory.Update(now, "current.example.com.", []netip.Addr{ip}, 3600)
	require.Equal(t, []string{"current.example.com"}, pg.GetNamesOf(epID, ip))
	require.Empty(t, pg.GetExpiredNamesOf(epID, ip))

	// Names only in DNSZombies are expired: they are reported by
	// GetExpiredNamesOf only, without trailing dot.
	expiredIP := netip.MustParseAddr("2.2.2.2")
	ep.DNSZombies.Upsert(now, expiredIP, "expired.example.com.")
	require.Empty(t, pg.GetNamesOf(epID, expiredIP))
	require.Equal(t, []string{"expired.example.com"}, pg.GetExpiredNamesOf(epID, expiredIP))

	// A name that is both current and expired is reported as current only.
	ep.DNSZombies.Upsert(now, ip, "current.example.com.", "stale.example.com.")
	require.Equal(t, []string{"current.example.com"}, pg.GetNamesOf(epID, ip))
	require.Equal(t, []string{"stale.example.com"}, pg.GetExpiredNamesOf(epID, ip))

	// If every expired name is also current, there is nothing to report.
	ep.DNSHistory.Update(now, "stale.example.com.", []netip.Addr{ip}, 3600)
	require.Empty(t, pg.GetExpiredNamesOf(epID, ip))

	// Unknown endpoints and invalid addresses resolve to nothing.
	require.Empty(t, pg.GetExpiredNamesOf(epID+1, expiredIP))
	require.Empty(t, pg.GetExpiredNamesOf(epID, netip.Addr{}))
}

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
