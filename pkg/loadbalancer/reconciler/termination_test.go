// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package reconciler

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestPrivilegedSocketTermination_ControlPlane(t *testing.T) {
	testutils.PrivilegedTest(t)

	for _, hostOnly := range []bool{true, false} {
		t.Run(fmt.Sprintf("hostOnly=%v", hostOnly), func(t *testing.T) {
			testSocketTermination(t, hostOnly)
		})
	}
}

func startSocketTerminationTestHive(
	t *testing.T,
	hostOnly bool,
	mock *mockDestroyer,
	syncChan testSyncChan,
	nsOps netnsOps,
) (*statedb.DB, statedb.RWTable[*loadbalancer.Backend]) {
	t.Helper()

	var (
		db       *statedb.DB
		backends statedb.RWTable[*loadbalancer.Backend]
	)
	h := hive.New(
		metrics.Cell,
		maglev.Cell,
		lbmaps.Cell,
		lbipamconfig.Cell,
		nodeipamconfig.Cell,
		loadbalancer.ConfigCell,

		cell.Provide(
			loadbalancer.NewBackendsTable,
			statedb.RWTable[*loadbalancer.Backend].ToTable,
			loadbalancer.NewFrontendsTable,
			statedb.RWTable[*loadbalancer.Frontend].ToTable,
			func() socketDestroyerFactory {
				return func(p socketTerminationParams) (sockets.SocketDestroyer, error) {
					return mock, nil
				}
			},
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
			func() testSyncChan { return syncChan },
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					UnsafeDaemonConfigOption: option.UnsafeDaemonConfig{
						BPFSocketLBHostnsOnly:                  hostOnly,
						EnableSocketLBPodConnectionTermination: true,
					},
					EnableIPv4: true,
					EnableIPv6: true,
				}
			},
			func() kpr.KPRConfig {
				return kpr.KPRConfig{
					KubeProxyReplacement: true,
					EnableSocketLB:       true,
				}
			},
			func() netnsOps { return nsOps },
		),
		cell.Invoke(registerSocketTermination),
		cell.Invoke(func(db_ *statedb.DB, backends_ statedb.RWTable[*loadbalancer.Backend]) {
			db = db_
			backends = backends_

		}),
	)

	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
		testutils.GoleakVerifyNone(t)
	})

	return db, backends
}

func testSocketTermination(t *testing.T, hostOnly bool) {
	var beAddr loadbalancer.L3n4Addr
	require.NoError(t, beAddr.ParseFromString("1.0.0.1:80/UDP"))

	mock := &mockDestroyer{
		requests: make(chan sockets.SocketFilter, 10),
	}

	syncChan := make(testSyncChan)

	visitedNamespaces := []*netns.NetNS{}
	hostNS := &netns.NetNS{}
	fooNS := &netns.NetNS{}

	db, backends := startSocketTerminationTestHive(t, hostOnly, mock, syncChan, netnsOps{
		current: func() (*netns.NetNS, error) {
			return hostNS, nil
		},
		do: func(ns *netns.NetNS, f func() error) error {
			visitedNamespaces = append(visitedNamespaces, ns)
			return f()
		},
		all: func() (iter.Seq2[string, *netns.NetNS], <-chan error) {
			errs := make(chan error)
			close(errs)
			return maps.All(map[string]*netns.NetNS{"foo": fooNS}), errs
		},
	})

	// Add a backends and wait for the job to pick it up
	wtxn := db.WriteTxn(backends)
	be := &loadbalancer.Backend{
		ServiceName: loadbalancer.NewServiceName("bar", "foo"),
		Address:     beAddr,
		State:       loadbalancer.BackendStateActive,
		Unhealthy:   false,
		Source:      source.Kubernetes,
	}
	be.SetSourcePriority(0)
	backends.Insert(wtxn, be)
	wtxn.Commit()

	// Wait until the first change has been seen
	<-syncChan

	wtxn = db.WriteTxn(backends)
	backends.DeleteAll(wtxn)
	wtxn.Commit()

	// We should see two deletions: one for host ns (if enabled) and one for the mocked
	// "foo" one.
	filter := <-mock.requests
	require.Equal(t, beAddr.Addr(), filter.DestIp, "IP matches")
	require.Equal(t, beAddr.Port(), filter.DestPort, "Port matches")

	if !hostOnly {
		filter = <-mock.requests
		require.Equal(t, beAddr.Addr(), filter.DestIp, "IP matches")
		require.Equal(t, beAddr.Port(), filter.DestPort, "Port matches")
		require.ElementsMatch(t, visitedNamespaces, []*netns.NetNS{hostNS, fooNS})
	} else {
		require.ElementsMatch(t, visitedNamespaces, []*netns.NetNS{hostNS})
	}
}

// Removing or disabling one reference to a shared backend must not request socket
// termination while another service or source has a live instance. Removing or
// disabling the last live reference must request termination.
func TestPrivilegedSocketTermination_ControlPlane_SharedBackend(t *testing.T) {
	testutils.PrivilegedTest(t)

	for _, tt := range []struct {
		name        string
		unhealthy   bool
		otherSource bool
		terminating bool
	}{
		{name: "deleted"},
		{name: "unhealthy", unhealthy: true},
		{name: "other-source", otherSource: true},
		{name: "terminating", terminating: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDestroyer{requests: make(chan sockets.SocketFilter, 3)}
			syncChan := make(testSyncChan)
			db, backends := startSocketTerminationTestHive(t, true, mock, syncChan, netnsOps{
				current: func() (*netns.NetNS, error) { return &netns.NetNS{}, nil },
				do:      func(_ *netns.NetNS, fn func() error) error { return fn() },
			})

			var sharedAddr, unsharedAddr loadbalancer.L3n4Addr
			require.NoError(t, sharedAddr.ParseFromString("1.0.0.1:80/UDP"))
			require.NoError(t, unsharedAddr.ParseFromString("1.0.0.2:80/UDP"))
			deleted := &loadbalancer.Backend{
				ServiceName: loadbalancer.NewServiceName("bar", "foo"),
				Address:     sharedAddr,
				State:       loadbalancer.BackendStateActive,
				Source:      source.Kubernetes,
			}
			surviving := deleted.Clone()
			surviving.ServiceName = loadbalancer.NewServiceName("other", "foo")
			if tt.otherSource {
				surviving.ServiceName = deleted.ServiceName
				surviving.Source = source.LocalAPI
				surviving.SetSourcePriority(1)
			}
			if tt.terminating {
				surviving.State = loadbalancer.BackendStateTerminating
			}
			unshared := deleted.Clone()
			unshared.ServiceName = loadbalancer.NewServiceName("other", "unshared")
			unshared.Address = unsharedAddr

			wtxn := db.WriteTxn(backends)
			defer wtxn.Abort()
			for _, be := range []*loadbalancer.Backend{deleted, surviving, unshared} {
				_, _, err := backends.Insert(wtxn, be)
				require.NoError(t, err)
			}
			wtxn.Commit()

			select {
			case <-syncChan:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for initial backend changes")
			}

			wtxn = db.WriteTxn(backends)
			defer wtxn.Abort()
			if tt.unhealthy {
				deleted = deleted.Clone()
				deleted.Unhealthy = true
				_, _, err := backends.Insert(wtxn, deleted)
				require.NoError(t, err)
			} else {
				_, hadOld, err := backends.Delete(wtxn, deleted)
				require.NoError(t, err)
				require.True(t, hadOld)
			}
			_, hadOld, err := backends.Delete(wtxn, unshared)
			require.NoError(t, err)
			require.True(t, hadOld)
			wtxn.Commit()
			remaining := []*loadbalancer.Backend{surviving}
			if tt.unhealthy {
				remaining = append(remaining, deleted)
			}
			require.ElementsMatch(t, remaining, statedb.Collect(backends.All(db.ReadTxn())))

			// Changes are processed in revision order. The unshared backend's request
			// confirms that the preceding shared backend change has been processed.
			// No request for the shared backend should precede it while a live instance remains.
			select {
			case filter := <-mock.requests:
				require.Equal(t, unsharedAddr.Addr(), filter.DestIp,
					"must not terminate a backend while a live instance remains")
				require.Equal(t, unsharedAddr.Port(), filter.DestPort)
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the unshared backend's socket termination request")
			}

			// Once no live instance remains, the shared backend's sockets should be terminated.
			wtxn = db.WriteTxn(backends)
			defer wtxn.Abort()
			if tt.unhealthy {
				surviving = surviving.Clone()
				surviving.Unhealthy = true
				_, _, err = backends.Insert(wtxn, surviving)
				require.NoError(t, err)
			} else {
				_, hadOld, err = backends.Delete(wtxn, surviving)
				require.NoError(t, err)
				require.True(t, hadOld)
			}
			wtxn.Commit()
			if tt.unhealthy {
				require.ElementsMatch(t, []*loadbalancer.Backend{deleted, surviving}, statedb.Collect(backends.All(db.ReadTxn())))
			} else {
				require.Empty(t, statedb.Collect(backends.All(db.ReadTxn())))
			}

			select {
			case filter := <-mock.requests:
				require.Equal(t, sharedAddr.Addr(), filter.DestIp)
				require.Equal(t, sharedAddr.Port(), filter.DestPort)
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the shared backend's socket termination request")
			}
		})
	}
}

type mockDestroyer struct {
	requests chan sockets.SocketFilter
}

// Destroy implements sockets.SocketDestroyer.
func (m *mockDestroyer) Destroy(logger *slog.Logger, filter sockets.SocketFilter) error {
	m.requests <- filter
	return nil
}

var _ sockets.SocketDestroyer = &mockDestroyer{}

func initializeNetns(t *testing.T, ns *netns.NetNS, addr string) net.Conn {
	var conn net.Conn
	assert.NoError(t, ns.Do(func() error {
		ls, err := safenetlink.LinkList()
		assert.NoError(t, err)
		for _, l := range ls {
			// Netns should be default created with loopback dev
			// we assign a localhost address to it to allow us to
			// bind sockets.
			if l.Attrs().Name == "lo" {
				netlink.AddrAdd(l, &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0xff),
					},
				})
			}
			_, err := safenetlink.AddrList(l, unix.AF_INET)
			assert.NoError(t, err)
		}
		conn, err = net.Dial("udp", addr)
		assert.NoError(t, err)
		conn.Write([]byte("ping"))
		return err
	}))
	return conn
}

func TestPrivilegedSocketTermination_Datapath(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns1, err := netns.New()
	require.NoError(t, err)
	// ns2 has a connection that should not be matched due
	// to a different port.
	ns2, err := netns.New()
	require.NoError(t, err)
	// ns3 will match revnat, but with a different cookie value
	// so we expect to avoid a socket close (i.e. this is
	// the case where we have matching tuple values, but
	// in an unexpected socket cookie value).
	ns3, err := netns.New()
	require.NoError(t, err)

	var conn1, conn2, conn3 net.Conn
	conn1 = initializeNetns(t, ns1, "127.0.0.1:30000")
	defer conn1.Close()

	conn2 = initializeNetns(t, ns2, "127.0.0.1:30002")
	defer conn2.Close()

	conn3 = initializeNetns(t, ns3, "127.0.0.1:30001")
	defer conn3.Close()

	getCookie := func(ns *netns.NetNS, port uint16) uint32 {
		if ns == nil {
			var err error
			ns, err = netns.Current()
			require.NoError(t, err)
		}
		out := uint32(0)
		ns.Do(func() error {
			sock, err := safenetlink.SocketDiagUDP(unix.AF_INET)
			assert.NoError(t, err)
			for _, s := range sock {
				if s.ID.DestinationPort == port {
					out = s.ID.Cookie[0]
					break
				}
			}
			return nil
		})
		return out
	}

	cookie := getCookie(ns1, 30000)

	extConfig := loadbalancer.ExternalConfig{
		BPFSocketLBHostnsOnly:                  false,
		EnableSocketLB:                         true,
		EnableSocketLBPodConnectionTermination: true,
		EnableIPv4:                             true,
		EnableIPv6:                             true,
	}

	// Set up the LBMaps implementation. Since we're running privileged this will
	// use an unpinned real BPF map.
	var lbmap lbmaps.LBMaps
	h := hive.New(
		metrics.Cell,
		maglev.Cell,
		lbmaps.Cell,
		cell.Config(loadbalancer.DefaultUserConfig),
		cell.Provide(
			loadbalancer.NewBackendsTable,
			statedb.RWTable[*loadbalancer.Backend].ToTable,
			loadbalancer.NewFrontendsTable,
			statedb.RWTable[*loadbalancer.Frontend].ToTable,
			loadbalancer.NewConfig,
			func() loadbalancer.ExternalConfig { return extConfig },
			func() *option.DaemonConfig { return &option.DaemonConfig{} },
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
			func() kpr.KPRConfig { return kpr.KPRConfig{} },
		),
		cell.Invoke(func(m lbmaps.LBMaps) {
			lbmap = m
		}),
	)

	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
		testutils.GoleakVerifyNone(t)
	})

	namespaces := map[string]*netns.NetNS{
		"cni-0000": ns1,
		"cni-0001": ns2,
		"cni-0002": ns3,
	}

	// Set up the parameters that [terminateConnectionsToBackend] needs.
	params := socketTerminationParams{
		JobGroup:  nil,
		DB:        nil,
		Backends:  nil,
		Log:       log,
		Config:    loadbalancer.DefaultConfig,
		ExtConfig: extConfig,
		LBMaps:    lbmap,
		NetNSOps: netnsOps{
			current: netns.Current,
			do:      (*netns.NetNS).Do,
			all: func() (iter.Seq2[string, *netns.NetNS], <-chan error) {
				errs := make(chan error)
				return func(yield func(string, *netns.NetNS) bool) {
					defer close(errs)
					for n, ns := range namespaces {
						if !yield(n, ns) {
							return
						}
					}
				}, errs
			},
		},
	}

	sd, err := sockets.NewSocketDestroyer(log, nil, nil)
	require.NoError(t, err)

	lbmap.UpdateSockRevNat(uint64(cookie), netip.MustParseAddr("127.0.0.1"), 30000, 0)

	ip, err := netip.ParseAddr("127.0.0.1")
	require.NoError(t, err)
	l4a := loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30000, 0)

	assertForceClose := func(closed bool, c net.Conn) {
		if closed {
			c.SetDeadline(time.Now().Add(time.Millisecond * 250))
			_, err = c.Read([]byte{0})
			assert.ErrorIs(t, err, unix.ECONNABORTED, "first sock connection should have been aborted")
		} else {
			c.SetDeadline(time.Now().Add(time.Millisecond * 250))
			_, err = c.Read([]byte{0})
			//nolint:errorlint
			assert.True(t, err.(net.Error).Timeout(),
				"other connection should not be prematurely closed, thus read cmd on the sock should simply be allowed to timeout")
		}
	}

	// 1. First, we have conn1 in ns1 which has:
	// 	* Is tracked in the l3nl4addr map.
	// 	* Real socket cookie.
	// 	* BPFSocketLBHostnsOnly is disabled
	// Therefore we expect a socket close.
	terminateConnectionsToBackend(params, sd, l4a)

	assertForceClose(true, conn1)
	assertForceClose(false, conn2)

	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30001, 0)
	terminateConnectionsToBackend(params, sd, l4a)
	assertForceClose(false, conn3)

	// 2. Will otherwise close, but we have lb host ns only enabled so we expect
	// 	connection to *not* close.
	assert.NoError(t, ns3.Do(func() error {
		conn3, err = net.Dial("udp", "127.0.0.1:30001")
		assert.NoError(t, err)
		return nil
	}))
	cookie3 := getCookie(ns3, 30001)
	lbmap.UpdateSockRevNat(uint64(cookie3), netip.MustParseAddr("127.0.0.1"), 30001, 0)
	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30001, 0)
	params.ExtConfig.BPFSocketLBHostnsOnly = true
	terminateConnectionsToBackend(params, sd, l4a)
	assertForceClose(false, conn3)

	// 3. Now we try a similar test, but with a connection in host ns
	// 	so this one should close.
	conn3, err = net.Dial("udp", "127.0.0.1:30004")
	assert.NoError(t, err)
	lbmap.UpdateSockRevNat(uint64(getCookie(nil, 30004)), netip.MustParseAddr("127.0.0.1"), 30004, 0)
	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30004, 0)
	terminateConnectionsToBackend(params, sd, l4a)
	assertForceClose(true, conn3)

	// 4. Now we try one in ns3 again, but we turn off lb host ns only so we expect a connection
	// 	to be closed.
	assert.NoError(t, ns3.Do(func() error {
		conn3, err = net.Dial("udp", "127.0.0.1:30003")
		assert.NoError(t, err)
		return nil
	}))
	cookie3 = getCookie(ns3, 30003)
	lbmap.UpdateSockRevNat(uint64(cookie3), netip.MustParseAddr("127.0.0.1"), 30003, 0)
	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30003, 0)

	params.ExtConfig.BPFSocketLBHostnsOnly = false
	terminateConnectionsToBackend(params, sd, l4a)
	assertForceClose(true, conn3)
}

// BenchmarkChangeIteration_TCP validates the CPU cost of processing unrelevant backend changes
// to judge whether the separation of this logic from the reconciler is worthwhile considering
// that we have to look at each changed Backend object.
func BenchmarkChangeIteration_TCP(b *testing.B) {
	benchmarkChangeIteration(b, loadbalancer.TCP)
}

// BenchmarkChangeIteration_UDP is the same as BenchmarkChangeIteration_TCP but
// each backend is a UDP backend, thus hitting the more costly "IsAlive()" check.
func BenchmarkChangeIteration_UDP(b *testing.B) {
	benchmarkChangeIteration(b, loadbalancer.UDP)
}

func benchmarkChangeIteration(b *testing.B, proto loadbalancer.L4Type) {
	// Skip the test by default as it uses fair bit of memory.
	b.Skip()

	db := statedb.New()
	backends, err := loadbalancer.NewBackendsTable(db)
	require.NoError(b, err)

	const numBackends = 1000000

	// Add some backends to iterate over
	wtxn := db.WriteTxn(backends)
	for i := range numBackends {
		addr := [4]byte{1, byte(i / (256 * 256)), byte(i / 256), byte(i % 256)}
		addrL3n4 := loadbalancer.NewL3n4Addr(
			proto,
			cmtypes.AddrClusterFrom(netip.AddrFrom4(addr), 0),
			1,
			loadbalancer.ScopeExternal,
		)
		be := loadbalancer.Backend{
			ServiceName: loadbalancer.NewServiceName("foo", "bar"),
			Address:     addrL3n4,
			Source:      source.Kubernetes,
			State:       loadbalancer.BackendStateActive,
			Unhealthy:   false,
		}
		be.SetSourcePriority(0)
		backends.Insert(wtxn, &be)
	}
	wtxn.Commit()

	b.ResetTimer()

	for b.Loop() {
		// Create the change iterator. This adds a bit of overhead, but since
		// we're doing massive amount of backends it won't change the result.
		wtxn := db.WriteTxn(backends)
		changeIter, err := backends.Changes(wtxn)
		require.NoError(b, err)
		rtxn := wtxn.Commit()

		changes, _ := changeIter.Next(rtxn)
		total, dead := 0, 0
		for change := range changes {
			backend := change.Object
			total++
			if change.Object.Address.Protocol() != loadbalancer.UDP {
				continue
			}
			if change.Deleted || !backend.IsAlive() {
				dead++
			}
		}

		require.Equal(b, numBackends, total)
		require.Equal(b, 0, dead)
	}

	b.ReportMetric(float64(b.N*numBackends)/b.Elapsed().Seconds(), "backends/sec")
	b.ReportMetric(float64(b.Elapsed())/float64(b.N*numBackends), "ns/backend")
}
