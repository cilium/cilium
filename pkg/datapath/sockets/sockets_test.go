// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/testutils"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/testutils/netns"

	"github.com/cilium/ebpf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestSocketReqSerialize(t *testing.T) {
	testCases := []struct {
		name     string
		req      SocketRequest
		expected []byte
	}{
		{
			name: "nil addresses",
			req: SocketRequest{
				Family:   2,
				Protocol: 6,
				Ext:      0,
				pad:      0,
				States:   4095,
				ID: netlink.SocketID{
					SourcePort:      0,
					DestinationPort: 0,
					Source:          nil,
					Destination:     nil,
					Interface:       0,
					Cookie:          [2]uint32{0, 0},
				},
			},
			expected: []byte{2, 6, 0, 0, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "non-nil addresses",
			req: SocketRequest{
				Family:   2,
				Protocol: 6,
				Ext:      0,
				pad:      0,
				States:   4095,
				ID: netlink.SocketID{
					SourcePort:      59212,
					DestinationPort: 30000,
					Source:          net.ParseIP("127.0.0.1"),
					Destination:     net.ParseIP("127.0.0.1"),
					Interface:       0,
					Cookie:          [2]uint32{4144, 0},
				},
			},
			expected: []byte{2, 6, 0, 0, 255, 15, 0, 0, 231, 76, 117, 48, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 16, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.req.Serialize())
		})
	}
}

func TestSocketDeserialize(t *testing.T) {
	testCases := []struct {
		name     string
		buf      []byte
		expected Socket
	}{
		{
			name: "default route addresses",
			buf:  []byte{2, 7, 0, 0, 170, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 89, 101, 0, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 157, 14, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
			expected: Socket{
				Family:  2,
				State:   7,
				Timer:   0,
				Retrans: 0,
				ID: netlink.SocketID{
					SourcePort:      43733,
					DestinationPort: 0,
					Source:          net.ParseIP("0.0.0.0"),
					Destination:     net.ParseIP("0.0.0.0"),
					Interface:       0,
					Cookie:          [2]uint32{8201, 0},
				},
				Expires: 0,
				RQueue:  0,
				WQueue:  0,
				UID:     108,
				INode:   25945,
			},
		},
		{
			name: "non default route addresses",
			buf:  []byte{2, 1, 0, 0, 189, 137, 1, 187, 192, 168, 50, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 99, 52, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 146, 138, 10, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 1, 42, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
			expected: Socket{
				Family:  2,
				State:   1,
				Timer:   0,
				Retrans: 0,
				ID: netlink.SocketID{
					SourcePort:      48521,
					DestinationPort: 443,
					Source:          net.ParseIP("192.168.50.194"),
					Destination:     net.ParseIP("151.99.52.13"),
					Interface:       0,
					Cookie:          [2]uint32{8211, 0},
				},
				Expires: 0,
				RQueue:  0,
				WQueue:  0,
				UID:     1000,
				INode:   690834,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var sock Socket
			err := sock.Deserialize(tc.buf)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, sock)
		})
	}
}

func BenchmarkSocketReqSerialize(b *testing.B) {
	requests := [...]SocketRequest{
		{
			Family:   2,
			Protocol: 6,
			Ext:      0,
			pad:      0,
			States:   4095,
			ID: netlink.SocketID{
				SourcePort:      0,
				DestinationPort: 0,
				Source:          nil,
				Destination:     nil,
				Interface:       0,
				Cookie:          [2]uint32{0, 0},
			},
		},
		{
			Family:   2,
			Protocol: 6,
			Ext:      0,
			pad:      0,
			States:   4095,
			ID: netlink.SocketID{
				SourcePort:      59212,
				DestinationPort: 30000,
				Source:          net.ParseIP("127.0.0.1"),
				Destination:     net.ParseIP("127.0.0.1"),
				Interface:       0,
				Cookie:          [2]uint32{4144, 0},
			},
		},
	}

	for b.Loop() {
		for _, req := range requests {
			req.Serialize()
		}
	}
}

func BenchmarkSocketDeserialize(b *testing.B) {
	buffers := [...][]byte{
		{2, 7, 0, 0, 170, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 89, 101, 0, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 157, 14, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
		{2, 1, 0, 0, 189, 137, 1, 187, 192, 168, 50, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 99, 52, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 146, 138, 10, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 1, 42, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
	}

	for b.Loop() {
		for _, buf := range buffers {
			var sock Socket
			sock.Deserialize(buf)
		}
	}
}

type socketDestroyerTester interface {
	SocketDestroyer
	PrepareAddress(network string, cookie uint64, addr any) error
	Reset() error
}

type testNetlinkSocketDestroyer struct {
	*netlinkSocketDestroyer
}

func newTestNetlinkSocketDestroyer(tb testing.TB) socketDestroyerTester {
	tb.Helper()

	return &testNetlinkSocketDestroyer{
		netlinkSocketDestroyer: &netlinkSocketDestroyer{},
	}
}

func (d *netlinkSocketDestroyer) PrepareAddress(network string, cookie uint64, addr any) error {
	return nil
}

func (d *netlinkSocketDestroyer) Reset() error {
	return nil
}

type testBPFSocketDestroyer struct {
	*bpfSocketDestroyer

	sockRevNat4Map *bpf.Map
	sockRevNat6Map *bpf.Map
}

func newTestBPFSocketDestroyer(tb testing.TB) socketDestroyerTester {
	tb.Helper()

	sockRevNat4Map := bpf.NewMap(maps.SockRevNat4MapName,
		ebpf.LRUHash,
		&maps.SockRevNat4Key{},
		&maps.SockRevNat4Value{},
		maps.MaxSockRevNat4MapEntries,
		0,
	)
	require.NoError(tb, sockRevNat4Map.OpenOrCreate())
	sockRevNat6Map := bpf.NewMap(maps.SockRevNat6MapName,
		ebpf.LRUHash,
		&maps.SockRevNat6Key{},
		&maps.SockRevNat6Value{},
		maps.MaxSockRevNat6MapEntries,
		0,
	)
	require.NoError(tb, sockRevNat6Map.OpenOrCreate())
	progs, filterSetter, err := loader.LoadSockTerm(hivetest.Logger(tb), sockRevNat4Map, sockRevNat6Map)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		progs.CilSockUdpDestroyV4.Close()
		progs.CilSockTcpDestroyV4.Close()
		progs.CilSockUdpDestroyV6.Close()
		progs.CilSockTcpDestroyV6.Close()
	})

	return &testBPFSocketDestroyer{
		bpfSocketDestroyer: &bpfSocketDestroyer{
			progs:        progs,
			filterSetter: filterSetter,
		},
		sockRevNat4Map: sockRevNat4Map,
		sockRevNat6Map: sockRevNat6Map,
	}
}

func (d *testBPFSocketDestroyer) PrepareAddress(network string, cookie uint64, addr any) error {
	var key bpf.MapKey
	var value bpf.MapValue
	var sockRevMap *bpf.Map
	var ip net.IP
	var port int

	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		ip = udpAddr.IP
		port = udpAddr.Port
	} else if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip = tcpAddr.IP
		port = tcpAddr.Port
	} else {
		return fmt.Errorf("unknown address type: %v", addr)
	}

	switch network {
	case "udp", "tcp":
		key = maps.NewSockRevNat4Key(cookie, ip, uint16(port))
		value = &maps.SockRevNat4Value{}
		sockRevMap = d.sockRevNat4Map
	case "udp6", "tcp6":
		key = maps.NewSockRevNat6Key(cookie, ip, uint16(port))
		value = &maps.SockRevNat6Value{}
		sockRevMap = d.sockRevNat6Map
	default:
		return fmt.Errorf("unknown network: %s", network)
	}

	return sockRevMap.Update(key, value)
}

func (d *testBPFSocketDestroyer) Reset() error {
	if err := d.sockRevNat4Map.DeleteAll(); err != nil {
		return err
	}
	if err := d.sockRevNat6Map.DeleteAll(); err != nil {
		return err
	}

	return nil
}

func makeSocketDestroyers(tb testing.TB) map[string]socketDestroyerTester {
	return map[string]socketDestroyerTester{
		"netlink": newTestNetlinkSocketDestroyer(tb),
		"bpf":     newTestBPFSocketDestroyer(tb),
	}
}

func startServer(tb testing.TB, network string, addr string) (any, error) {
	var serverAddr any
	var listener io.Closer
	var err error

	switch network {
	case "udp", "udp6":
		serverAddr, err = net.ResolveUDPAddr(network, addr)
		if err != nil {
			return nil, fmt.Errorf("resolving UDP address: %w", err)
		}
		listener, err = net.ListenUDP(network, serverAddr.(*net.UDPAddr))
		if err != nil {
			return nil, fmt.Errorf("start listening: %w", err)
		}
	case "tcp", "tcp6":
		serverAddr, err = net.ResolveTCPAddr(network, addr)
		if err != nil {
			return nil, fmt.Errorf("resolving TCP address: %w", err)
		}
		listener, err = net.ListenTCP(network, serverAddr.(*net.TCPAddr))
		if err != nil {
			return nil, fmt.Errorf("start listening: %w", err)
		}
	}

	tb.Cleanup(func() {
		listener.Close()
	})
	return serverAddr, nil
}

func prepareConnectionsAndMaps(t *testing.T, servers map[string][]string, sdt socketDestroyerTester) (map[string][]net.Conn, error) {
	conns := make(map[string][]net.Conn)

	for addr, networks := range servers {
		for _, network := range networks {
			connectAddr, err := startServer(t, network, addr)
			if err != nil {
				return nil, fmt.Errorf("starting server: %w", err)
			}
			conn, err := net.Dial(network, addr)
			if err != nil {
				return nil, fmt.Errorf("dialing %s/%s: %w", network, addr, err)
			}
			t.Cleanup(func() {
				conn.Close()
			})
			sysConn, ok := conn.(syscall.Conn)
			if !ok {
				return nil, fmt.Errorf("conn is not a syscall.Conn")
			}
			rawConn, err := sysConn.SyscallConn()
			if err != nil {
				return nil, fmt.Errorf("getting raw connection: %w", err)
			}
			var cookie uint64
			rawConn.Control(func(fd uintptr) {
				cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
			})
			if err != nil {
				return nil, fmt.Errorf("getting socket cookie: %w", err)
			}
			if err := sdt.PrepareAddress(network, cookie, connectAddr); err != nil {
				return nil, fmt.Errorf("preparing socket filter %s/%s %v: %w", network, addr, cookie, err)
			}
			conns[addr] = append(conns[addr], conn)
		}
	}

	return conns, nil
}

func checkForClosedSockets(conns map[string][]net.Conn) (map[string]bool, map[string]bool) {
	udpClosed := make(map[string]bool)
	tcpClosed := make(map[string]bool)

	for addr, addrConns := range conns {
		for _, conn := range addrConns {
			var b [8]byte
			_, err := conn.Write(b[:])
			if err != nil {
				if _, ok := conn.(*net.UDPConn); ok {
					udpClosed[addr] = true
				} else {
					tcpClosed[addr] = true
				}
			}
		}
	}

	return udpClosed, tcpClosed
}

func TestPrivilegedSocketDestroyers(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	socketDestroyers := makeSocketDestroyers(t)
	servers := map[string][]string{
		"127.0.0.1:8888": {"udp", "tcp"},
		"[::1]:8888":     {"udp6", "tcp6"},
		"127.0.0.1:8889": {"udp", "tcp"},
		"[::1]:8889":     {"udp6", "tcp6"},
	}
	testCases := map[string]struct {
		filter         SocketFilter
		expectUDPClose []string
		expectTCPClose []string
	}{
		"close 127.0.0.1:8888 (UDP)": {
			filter: SocketFilter{
				DestIp:   net.IP{127, 0, 0, 1},
				DestPort: 8888,
				Family:   unix.AF_INET,
				Protocol: unix.IPPROTO_UDP,
				States:   StateFilterUDP,
			},
			expectUDPClose: []string{
				"127.0.0.1:8888",
			},
		},
		"close 127.0.0.1:8888 (TCP)": {
			filter: SocketFilter{
				DestIp:   net.IP{127, 0, 0, 1},
				DestPort: 8888,
				Family:   unix.AF_INET,
				Protocol: unix.IPPROTO_TCP,
				States:   StateFilterTCP,
			},
			expectTCPClose: []string{
				"127.0.0.1:8888",
			},
		},
		"close [::1]:8888 (UDP)": {
			filter: SocketFilter{
				DestIp:   net.IPv6loopback,
				DestPort: 8888,
				Family:   unix.AF_INET6,
				Protocol: unix.IPPROTO_UDP,
				States:   StateFilterUDP,
			},
			expectUDPClose: []string{
				"[::1]:8888",
			},
		},
		"close [::1]:8888 (TCP)": {
			filter: SocketFilter{
				DestIp:   net.IPv6loopback,
				DestPort: 8888,
				Family:   unix.AF_INET6,
				Protocol: unix.IPPROTO_TCP,
				States:   StateFilterTCP,
			},
			expectTCPClose: []string{
				"[::1]:8888",
			},
		},
	}

	for dName, sockDestroyer := range socketDestroyers {
		t.Run(dName, func(t *testing.T) {
			for name, tc := range testCases {
				t.Run(name, func(t *testing.T) {
					ns := netns.NewNetNS(t)
					defer ns.Close()
					defer sockDestroyer.Reset()

					var link netlink.Link
					var err error

					require.NoError(t, ns.Do(func() error {
						link, err = safenetlink.LinkByName("lo")
						if err != nil {
							return err
						}
						return netlink.LinkSetUp(link)
					}))

					var conns map[string][]net.Conn
					require.NoError(t, ns.Do(func() error {
						conns, err = prepareConnectionsAndMaps(t, servers, sockDestroyer)
						return err
					}))

					require.NoError(t, ns.Do(func() error {
						return sockDestroyer.Destroy(log, tc.filter)
					}))

					var udpClosed map[string]bool
					var tcpClosed map[string]bool
					_ = ns.Do(func() error {
						udpClosed, tcpClosed = checkForClosedSockets(conns)
						return nil
					})

					require.Len(t, udpClosed, len(tc.expectUDPClose))
					for _, addr := range tc.expectUDPClose {
						require.Contains(t, udpClosed, addr)
					}

					require.Len(t, tcpClosed, len(tc.expectTCPClose))
					for _, addr := range tc.expectTCPClose {
						require.Contains(t, tcpClosed, addr)
					}
				})
			}
		})
	}
}

func BenchmarkDestroyers(b *testing.B) {
	socketDestroyers := makeSocketDestroyers(b)
	log := hivetest.Logger(b)

	for name, sockDestroyer := range socketDestroyers {
		b.Run(name, func(b *testing.B) {
			addr := "127.0.0.1:8888"
			startServer(b, "udp", addr)

			for i := 0; i < b.N; i++ {
				conn, err := net.Dial("udp", addr)
				if err != nil {
					b.Fatalf("connecting: %v", err)
				}
				defer conn.Close()

				require.NoError(b, sockDestroyer.Destroy(log, SocketFilter{
					DestIp:   net.IPv4(127, 0, 0, 1),
					DestPort: 8888,
					Family:   unix.AF_INET,
					Protocol: unix.IPPROTO_UDP,
				}))
			}
		})
	}
}
