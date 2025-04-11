// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/maps/filter"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/testutils/netns"

	"github.com/cilium/ebpf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bpfSockTerm = "bpf_sock_term.o"
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

const (
	servAddr = "127.0.0.1:0"
)

func setupAndRunTest(t *testing.T, n int, proto netlink.Proto, testFn func(t *testing.T, clientConns []net.Conn)) {
	conns := []net.Conn{}
	for range n {
		u8p, err := u8proto.FromNumber(uint8(proto))
		assert.NoError(t, err)

		var lis net.Listener
		var dst string
		if proto == unix.IPPROTO_TCP {
			lis, err = net.Listen(strings.ToLower(u8p.String()), servAddr)
			require.NoError(t, err)
			go func() {
				conn, err := lis.Accept()
				for {
					require.NoError(t, err)
					buf := make([]byte, 1)
					_, err := conn.Read(buf)
					if errors.Is(err, io.EOF) {
						return
					}
				}
			}()
			dst = lis.Addr().String()
		} else {
			dst = "127.0.0.0:8080"
		}

		clientConn, err := net.Dial(strings.ToLower(u8p.String()), dst)
		require.NoError(t, err)
		_, err = clientConn.Write([]byte("ping"))
		assert.NoError(t, err)
		defer clientConn.Close()
		conns = append(conns, clientConn)
	}
	testFn(t, conns)
}

type socketDestroyerTester interface {
	SocketDestroyer

	PrepareAddress(network string, cookie uint64, addr *net.UDPAddr) error
	Reset() error
}

type netlinkSocketDestroyer struct {
	*NetlinkSocketDestroyer
}

func newNetlinkSocketDestroyer(tb testing.TB) socketDestroyerTester {
	tb.Helper()

	return &netlinkSocketDestroyer{
		NetlinkSocketDestroyer: &NetlinkSocketDestroyer{
			Logger: hivetest.Logger(tb),
		},
	}
}

func (d *netlinkSocketDestroyer) PrepareAddress(network string, cookie uint64, addr *net.UDPAddr) error {
	return nil
}

func (d *netlinkSocketDestroyer) Reset() error {
	return nil
}

type bpfSocketDestroyer struct {
	*BPFSocketDestroyer

	sockRevNat4Map *bpf.Map
	sockRevNat6Map *bpf.Map
}

func newBPFSocketDestroyer(tb testing.TB) socketDestroyerTester {
	tb.Helper()

	pinPath := testutils.TempBPFFS(tb)
	origPath := loader.BPFSockTermPath
	loader.BPFSockTermPath = testutils.FindInPath(tb, bpfSockTerm)
	tb.Cleanup(func() {
		loader.BPFSockTermPath = origPath
	})

	sockRevNat4Map := bpf.NewMap(lbmap.SockRevNat4MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat4Key{},
		&lbmap.SockRevNat4Value{},
		lbmap.MaxSockRevNat4MapEntries,
		0,
	).WithPinPath(filepath.Join(pinPath, lbmap.SockRevNat6MapName))
	require.NoError(tb, sockRevNat4Map.OpenOrCreate())
	sockRevNat6Map := bpf.NewMap(lbmap.SockRevNat6MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat6Key{},
		&lbmap.SockRevNat6Value{},
		lbmap.MaxSockRevNat6MapEntries,
		0,
	).WithPinPath(filepath.Join(pinPath, lbmap.SockRevNat6MapName))
	require.NoError(tb, sockRevNat6Map.OpenOrCreate())
	sockTermFilter := filter.NewSockTermFilterMap()
	sockTermFilter.Map.WithPinPath(filepath.Join(pinPath, filter.SockTermFilterMapName))
	require.NoError(tb, sockTermFilter.OpenOrCreate())
	prog, err := loader.LoadSockTerm(pinPath)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		prog.Close()
	})

	return &bpfSocketDestroyer{
		BPFSocketDestroyer: &BPFSocketDestroyer{
			prog:           prog,
			SockTermFilter: sockTermFilter,
			Logger:         hivetest.Logger(tb),
		},
		sockRevNat4Map: sockRevNat4Map,
		sockRevNat6Map: sockRevNat6Map,
	}
}

func (d *bpfSocketDestroyer) PrepareAddress(network string, cookie uint64, addr *net.UDPAddr) error {
	var key bpf.MapKey
	var value bpf.MapValue
	var sockRevMap *bpf.Map

	switch network {
	case "udp":
		key = lbmap.NewSockRevNat4Key(cookie, addr.IP, uint16(addr.Port))
		value = &lbmap.SockRevNat4Value{}
		sockRevMap = d.sockRevNat4Map
	case "udp6":
		key = lbmap.NewSockRevNat6Key(cookie, addr.IP, uint16(addr.Port))
		value = &lbmap.SockRevNat6Value{}
		sockRevMap = d.sockRevNat6Map
	default:
		return fmt.Errorf("unknown network: %s", network)
	}

	return sockRevMap.Update(key, value)
}

func (d *bpfSocketDestroyer) Reset() error {
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
		"netlink": newNetlinkSocketDestroyer(tb),
		"bpf":     newBPFSocketDestroyer(tb),
	}
}

func startServer(tb testing.TB, network string, addr string) *net.UDPAddr {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	require.NoError(tb, err)
	conn, err := net.ListenUDP(network, udpAddr)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		conn.Close()
	})
	return udpAddr
}

func TestSocketDestroyers(t *testing.T) {
	testutils.PrivilegedTest(t)

	socketDestroyers := makeSocketDestroyers(t)
	servers := map[string]string{
		"127.0.0.1:8888": "udp",
		"[::1]:8888":     "udp6",
		"127.0.0.1:8889": "udp",
		"[::1]:8889":     "udp6",
	}
	testCases := map[string]struct {
		filter      SocketFilter
		expectClose []string
	}{
		"close 127.0.0.1:8888": {
			filter: SocketFilter{
				DestIp:   net.IP{127, 0, 0, 1},
				DestPort: 8888,
				Family:   unix.AF_INET,
				Protocol: unix.IPPROTO_UDP,
			},
			expectClose: []string{
				"127.0.0.1:8888",
			},
		},
		"close [::1]:8888": { // This test case fails
			filter: SocketFilter{
				DestIp:   net.IPv6loopback,
				DestPort: 8888,
				Family:   unix.AF_INET6,
				Protocol: unix.IPPROTO_UDP,
			},
			expectClose: []string{
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

					_ = ns.Do(func() error {
						conns := make(map[string]net.Conn)
						link, err := netlink.LinkByName("lo")
						require.NoError(t, err)
						require.NoError(t, netlink.LinkSetUp(link))

						for addr, network := range servers {
							udpAddr := startServer(t, network, addr)
							conn, err := net.Dial(network, addr)
							require.NoError(t, err)
							defer conn.Close()
							rawConn, err := conn.(*net.UDPConn).SyscallConn()
							require.NoError(t, err)
							var cookie uint64
							rawConn.Control(func(fd uintptr) {
								cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
							})
							require.NoError(t, err)
							require.NoError(t, sockDestroyer.PrepareAddress(network, cookie, udpAddr))
							conns[addr] = conn
						}

						require.NoError(t, sockDestroyer.Destroy(tc.filter))

						closed := make(map[string]bool)
						for addr, conn := range conns {
							var b [8]byte
							_, err := conn.Write(b[:])
							if err != nil {
								closed[addr] = true
								delete(conns, addr)
							}
						}

						require.Len(t, closed, len(tc.expectClose))
						for _, addr := range tc.expectClose {
							require.Contains(t, closed, addr)
						}

						return nil
					})
				})
			}
		})
	}
}

func BenchmarkDestroyers(b *testing.B) {
	socketDestroyers := makeSocketDestroyers(b)

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

				require.NoError(b, sockDestroyer.Destroy(SocketFilter{
					DestIp:   net.IPv4(127, 0, 0, 1),
					DestPort: 8888,
					Family:   unix.AF_INET,
					Protocol: unix.IPPROTO_UDP,
				}))
			}
		})
	}
}

func TestIterateAndDestroy(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)
	setupAndRunTest(t, 1, unix.IPPROTO_TCP, func(t *testing.T, clientConns []net.Conn) {
		var conn net.Conn
		for _, conn = range clientConns {
			break
		}
		destroyed := false
		assert.NoError(t, Iterate(unix.IPPROTO_TCP, unix.AF_INET, 0xff, func(s *netlink.Socket, err error) error {
			if s == nil {
				return nil
			}
			if conn.RemoteAddr().String() == fmt.Sprintf("%s:%d", s.ID.Destination.String(), s.ID.DestinationPort) {
				destroyed = true
				assert.NoError(t, DestroySocket(log, *s, unix.IPPROTO_TCP, 0xffff))
			}

			return nil
		}))
		assert.True(t, destroyed)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			for _, conn := range clientConns {
				_, err := conn.Read([]byte{0})
				assert.Error(collect, err)
			}
		}, time.Second*3, time.Millisecond*50)
	})
	setupAndRunTest(t, 1, unix.IPPROTO_UDP, func(t *testing.T, clientConns []net.Conn) {
		var conn net.Conn
		for _, conn = range clientConns {
			break
		}
		destroyed := false
		assert.NoError(t, Iterate(unix.IPPROTO_UDP, unix.AF_INET, 0xff, func(s *netlink.Socket, err error) error {
			if s == nil {
				return nil
			}
			if conn.RemoteAddr().String() == fmt.Sprintf("%s:%d", s.ID.Destination.String(), s.ID.DestinationPort) {
				destroyed = true
				assert.NoError(t, DestroySocket(log, *s, unix.IPPROTO_UDP, 0xffff))
			}

			return nil
		}))
		assert.True(t, destroyed)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			for _, conn := range clientConns {
				_, err := conn.Read([]byte{0})
				assert.Error(collect, err)
			}
		}, time.Second*3, time.Millisecond*50)
	})
}
