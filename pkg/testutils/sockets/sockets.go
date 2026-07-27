// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testsockets

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/sockets"
)

type MockSockets struct {
	sockets []*MockSocket
}

type MockSocket struct {
	SockID    netlink.SocketID
	Family    uint8
	Protocol  uint8
	Destroyed bool
}

func NewMockSockets(sockets []*MockSocket) *MockSockets {
	mocks := &MockSockets{sockets: make([]*MockSocket, len(sockets))}
	for i := range mocks.sockets {
		mocks.sockets[i] = sockets[i]
	}
	return mocks
}

func (s *MockSockets) Destroy(filter sockets.SocketFilter) error {
	for _, socket := range s.sockets {
		if filter.MatchSocket(socket.SockID) && filter.Family == socket.Family &&
			filter.Protocol == socket.Protocol {
			socket.Destroyed = true
		}
	}

	return nil
}

func (s *MockSocket) Equal(s2 *MockSocket) bool {
	return s.SockID.Destination.Equal(s2.SockID.Destination) &&
		s.SockID.DestinationPort == s2.SockID.DestinationPort &&
		s.Family == s2.Family && s.Protocol == s2.Protocol
}
