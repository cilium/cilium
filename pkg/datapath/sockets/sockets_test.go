// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"

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

func TestDestroy(t *testing.T) {
	testutils.PrivilegedTest(t)
	n := 3
	log := hivetest.Logger(t)
	setupAndRunTest(t, n, unix.IPPROTO_UDP, func(t *testing.T, conns []net.Conn) {
		var cc net.Conn
		for _, cc = range conns {
			break
		}

		addr := cc.RemoteAddr().String()
		toks := strings.Split(addr, ":")
		dport, err := strconv.Atoi(toks[1])
		assert.NoError(t, err)
		daddr := net.ParseIP(toks[0])
		matches := 0
		assert.NoError(t, Destroy(log, SocketFilter{
			DestIp:   daddr,
			DestPort: uint16(dport),
			Family:   unix.AF_INET,
			Protocol: unix.IPPROTO_UDP,
			States:   StateFilterUDP,
			DestroyCB: func(id netlink.SocketID) bool {
				matches++
				return true
			},
		}))
		assert.Equal(t, n, matches)
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			for _, conn := range conns {
				_, err := conn.Read([]byte{0})
				assert.ErrorIs(collect, err, syscall.ECONNABORTED)
			}
		}, time.Second*3, time.Millisecond*50)
	})
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
