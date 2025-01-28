// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
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

	for i := 0; i < b.N; i++ {
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

	for i := 0; i < b.N; i++ {
		for _, buf := range buffers {
			var sock Socket
			sock.Deserialize(buf)
		}
	}
}
