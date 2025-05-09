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
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestSocketTermination_ControlPlane(t *testing.T) {
	testutils.PrivilegedTest(t)

	for _, hostOnly := range []bool{true, false} {
		t.Run(fmt.Sprintf("hostOnly=%v", hostOnly), func(t *testing.T) {
			testSocketTermination(t, hostOnly)
		})
	}
}

func testSocketTermination(t *testing.T, hostOnly bool) {
	var beAddr loadbalancer.L3n4Addr
	require.NoError(t, beAddr.ParseFromString("1.0.0.1:80/UDP"))

	var (
		db       *statedb.DB
		backends statedb.RWTable[*loadbalancer.Backend]
	)
	mock := &mockDestroyer{
		requests: make(chan sockets.SocketFilter, 10),
	}

	syncChan := make(testSyncChan)

	visitedNamespaces := []*netns.NetNS{}
	hostNS := &netns.NetNS{}
	fooNS := &netns.NetNS{}

	h := hive.New(
		maglev.Cell,
		lbmaps.Cell,
		loadbalancer.ConfigCell,

		cell.Provide(
			loadbalancer.NewBackendsTable,
			statedb.RWTable[*loadbalancer.Backend].ToTable,
			func() sockets.SocketDestroyer { return mock },
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
			func() testSyncChan { return syncChan },
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					BPFSocketLBHostnsOnly:                  hostOnly,
					EnableSocketLB:                         true,
					EnableSocketLBPodConnectionTermination: true,
					EnableIPv4:                             true,
					EnableIPv6:                             true,
				}
			},
			func() netnsOps {
				return netnsOps{
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
						return maps.All(map[string]*netns.NetNS{
							"foo": fooNS,
						}), errs
					},
				}
			},
		),
		cell.Module("test", "test",
			cell.Invoke(registerSocketTermination),
		),
		cell.Invoke(func(db_ *statedb.DB, backends_ statedb.RWTable[*loadbalancer.Backend]) {
			db = db_
			backends = backends_

		}),
	)

	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
		goleak.VerifyNone(t)
	})

	// Add a backends and wait for the job to pick it up
	wtxn := db.WriteTxn(backends)
	backends.Insert(wtxn, &loadbalancer.Backend{Address: beAddr})
	wtxn.Commit()

	// Wait until the first change has been seen
	<-syncChan

	wtxn = db.WriteTxn(backends)
	backends.DeleteAll(wtxn)
	wtxn.Commit()

	// We should see two deletions: one for host ns (if enabled) and one for the mocked
	// "foo" one.
	filter := <-mock.requests
	require.True(t, beAddr.AddrCluster.AsNetIP().Equal(filter.DestIp), "IP matches")
	require.Equal(t, beAddr.Port, filter.DestPort, "Port matches")

	if !hostOnly {
		filter = <-mock.requests
		require.True(t, beAddr.AddrCluster.AsNetIP().Equal(filter.DestIp), "IP matches")
		require.Equal(t, beAddr.Port, filter.DestPort, "Port matches")
		require.ElementsMatch(t, visitedNamespaces, []*netns.NetNS{hostNS, fooNS})
	} else {
		require.ElementsMatch(t, visitedNamespaces, []*netns.NetNS{hostNS})
	}

}

type mockDestroyer struct {
	requests chan sockets.SocketFilter
}

// Destroy implements sockets.SocketDestroyer.
func (m *mockDestroyer) Destroy(filter sockets.SocketFilter) error {
	m.requests <- filter
	return nil
}

var _ sockets.SocketDestroyer = &mockDestroyer{}

func initializeNetns(t *testing.T, ns *netns.NetNS, addr string) net.Conn {
	var conn net.Conn
	assert.NoError(t, ns.Do(func() error {
		ls, err := netlink.LinkList()
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
			_, err := netlink.AddrList(l, unix.AF_INET)
			assert.NoError(t, err)
		}
		conn, err = net.Dial("udp", addr)
		assert.NoError(t, err)
		conn.Write([]byte("ping"))
		return err
	}))
	return conn
}

func TestSocketTermination_Datapath(t *testing.T) {
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
			sock, err := netlink.SocketDiagUDP(unix.AF_INET)
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
		maglev.Cell,
		lbmaps.Cell,
		cell.Config(loadbalancer.DefaultUserConfig),
		cell.Config(loadbalancer.DeprecatedConfig{}),
		cell.Provide(
			loadbalancer.NewConfig,
			func() loadbalancer.ExternalConfig { return extConfig },
			func() *option.DaemonConfig { return &option.DaemonConfig{} },
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
		),
		cell.Invoke(func(m lbmaps.LBMaps) {
			lbmap = m
		}),
	)

	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
		goleak.VerifyNone(t)
	})

	// Set up the parameters that [terminateUDPConnectionsToBackend] needs.
	params := socketTerminationParams{
		JobGroup:        nil,
		DB:              nil,
		Backends:        nil,
		Log:             log,
		Config:          loadbalancer.DefaultConfig,
		ExtConfig:       extConfig,
		LBMaps:          lbmap,
		SocketDestroyer: &socketDestroyer{log},
		NetNSOps: netnsOps{
			current: netns.Current,
			do:      (*netns.NetNS).Do,
			all: func() (iter.Seq2[string, *netns.NetNS], <-chan error) {
				errs := make(chan error)
				close(errs)
				return maps.All(map[string]*netns.NetNS{
					"cni-0000": ns1,
					"cni-0001": ns2,
					"cni-0002": ns3,
				}), errs
			},
		},
	}

	lbmap.UpdateSockRevNat(uint64(cookie), net.IP{127, 0, 0, 1}, 30000, 0)

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
	terminateUDPConnectionsToBackend(params, *l4a)

	assertForceClose(true, conn1)
	assertForceClose(false, conn2)

	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30001, 0)
	terminateUDPConnectionsToBackend(params, *l4a)
	assertForceClose(false, conn3)

	// 2. Will otherwise close, but we have lb host ns only enabled so we expect
	// 	connection to *not* close.
	assert.NoError(t, ns3.Do(func() error {
		conn3, err = net.Dial("udp", "127.0.0.1:30001")
		assert.NoError(t, err)
		return nil
	}))
	cookie3 := getCookie(ns3, 30001)
	lbmap.UpdateSockRevNat(uint64(cookie3), net.IP{127, 0, 0, 1}, 30001, 0)
	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30001, 0)
	params.ExtConfig.BPFSocketLBHostnsOnly = true
	terminateUDPConnectionsToBackend(params, *l4a)
	assertForceClose(false, conn3)

	// 3. Now we try a similar test, but with a connection in host ns
	// 	so this one should close.
	conn3, err = net.Dial("udp", "127.0.0.1:30004")
	assert.NoError(t, err)
	lbmap.UpdateSockRevNat(uint64(getCookie(nil, 30004)), net.IP{127, 0, 0, 1}, 30004, 0)
	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30004, 0)
	terminateUDPConnectionsToBackend(params, *l4a)
	assertForceClose(true, conn3)

	// 4. Now we try one in ns3 again, but we turn off lb host ns only so we expect a connection
	// 	to be closed.
	assert.NoError(t, ns3.Do(func() error {
		conn3, err = net.Dial("udp", "127.0.0.1:30003")
		assert.NoError(t, err)
		return nil
	}))
	cookie3 = getCookie(ns3, 30003)
	lbmap.UpdateSockRevNat(uint64(cookie3), net.IP{127, 0, 0, 1}, 30003, 0)
	l4a = loadbalancer.NewL3n4Addr(loadbalancer.UDP, cmtypes.AddrClusterFrom(ip, 0), 30003, 0)

	params.ExtConfig.BPFSocketLBHostnsOnly = false
	terminateUDPConnectionsToBackend(params, *l4a)
	assertForceClose(true, conn3)
}
