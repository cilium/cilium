// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"sync"
	"testing"

	hivecell "github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hubble/parser/nodes"
	parserOptions "github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node/manager"
)

type fakeNodeManagerForNodeLabels struct {
	manager.NodeManager

	mu               sync.Mutex
	subscribeCalls   int
	unsubscribeCalls int
}

func (f *fakeNodeManagerForNodeLabels) SubscribeNodeState(manager.NodeStateObserver) {
	f.mu.Lock()
	f.subscribeCalls++
	f.mu.Unlock()
}

func (f *fakeNodeManagerForNodeLabels) UnsubscribeNodeState(manager.NodeStateObserver) {
	f.mu.Lock()
	f.unsubscribeCalls++
	f.mu.Unlock()
}

func (f *fakeNodeManagerForNodeLabels) calls() (subscribe, unsubscribe int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subscribeCalls, f.unsubscribeCalls
}

func TestNodeLabelsResolverProviderSharesGetterAndLifecycle(t *testing.T) {
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: context.Background(),
		Logger:  hivetest.Logger(t),
	})
	t.Cleanup(func() { require.NoError(t, ipc.Shutdown()) })
	nodeManager := &fakeNodeManagerForNodeLabels{}

	var (
		parserOpts []parserOptions.Option
		lifecycle  nodes.DirectionalNodeLabelsLifecycle
	)
	h := hive.New(
		hivecell.Provide(
			newDirectionalNodeLabelsResolver,
			func() *ipcache.IPCache { return ipc },
			func() manager.NodeManager { return nodeManager },
			func() cmtypes.ClusterInfo {
				return cmtypes.ClusterInfo{ID: 10, Name: "local"}
			},
		),
		hivecell.Invoke(func(in struct {
			hivecell.In

			ParserOptions []parserOptions.Option `group:"hubble-parser-options"`
			Lifecycle     nodes.DirectionalNodeLabelsLifecycle
		}) {
			parserOpts = in.ParserOptions
			lifecycle = in.Lifecycle
		}),
	)

	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.Background()))
	subscribe, unsubscribe := nodeManager.calls()
	require.Zero(t, subscribe, "construction and Hive start must not subscribe")
	require.Zero(t, unsubscribe)
	require.Len(t, parserOpts, 1)
	require.NotNil(t, lifecycle)

	var opts parserOptions.Options
	parserOpts[0](&opts)
	require.Same(t, opts.NodeLabelsGetter, lifecycle,
		"the grouped getter and lifecycle must expose the same resolver")

	require.NoError(t, lifecycle.Start())
	lifecycle.Stop()                                      // launch-error cleanup
	require.NoError(t, h.Stop(log, context.Background())) // normal OnStop cleanup
	subscribe, unsubscribe = nodeManager.calls()
	require.Equal(t, 1, subscribe)
	require.Equal(t, 1, unsubscribe,
		"launch-error cleanup followed by Hive OnStop must be idempotent")
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
