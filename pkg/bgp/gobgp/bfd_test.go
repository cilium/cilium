// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/testutils"
	"github.com/cilium/cilium/pkg/bgp/types"
)

const (
	testBFDPort       = testutils.BFDPort
	testBFDInterval   = testutils.BFDInterval
	testBFDMultiplier = testutils.BFDMultiplier
)

func TestBFDIntegration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("BFD integration tests require Linux loopback addressing and socket options")
	}
	testutils.LockBFDIntegrationTests(t)

	t.Run("session reaches up and expires", func(t *testing.T) {
		peer := newTestBFDPeer(t, "127.0.0.2")
		router := newTestBFDRouter(t, "127.0.0.1")
		neighbor := testBFDNeighbor("127.0.0.2")

		require.NoError(t, router.AddNeighbor(context.Background(), neighbor))
		requireBFDState(t, router, neighbor.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)

		state, found := getBFDState(router, neighbor.Address)
		require.True(t, found)
		require.Positive(t, state.BfdAsync.ReceivedPackets)
		require.Positive(t, state.BfdAsync.TransmittedPackets)

		peerState, err := router.GetPeerState(context.Background(), &types.GetPeerStateRequest{})
		require.NoError(t, err)
		require.Len(t, peerState.Peers, 1)
		require.Equal(t, types.BFDSessionUp, peerState.Peers[0].BFD.SessionState)

		peer.SetResponding(false)
		requireBFDState(t, router, neighbor.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_DOWN)
	})

	t.Run("multiple sessions have independent state", func(t *testing.T) {
		peerA := newTestBFDPeer(t, "127.0.0.2")
		newTestBFDPeer(t, "127.0.0.3")
		router := newTestBFDRouter(t, "127.0.0.1")
		neighborA := testBFDNeighbor("127.0.0.2")
		neighborB := testBFDNeighbor("127.0.0.3")

		require.NoError(t, router.AddNeighbor(context.Background(), neighborA))
		require.NoError(t, router.AddNeighbor(context.Background(), neighborB))
		requireBFDState(t, router, neighborA.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)
		requireBFDState(t, router, neighborB.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)

		peerA.SetResponding(false)
		requireBFDState(t, router, neighborA.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_DOWN)
		requireBFDState(t, router, neighborB.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)
	})

	t.Run("BFD can be enabled and disabled by updating a neighbor", func(t *testing.T) {
		newTestBFDPeer(t, "127.0.0.2")
		router := newTestBFDRouter(t, "127.0.0.1")
		neighbor := testBFDNeighbor("127.0.0.2")
		neighbor.BFD = nil

		require.NoError(t, router.AddNeighbor(context.Background(), neighbor))
		require.Never(t, func() bool {
			_, found := getBFDState(router, neighbor.Address)
			return found
		}, 500*time.Millisecond, 25*time.Millisecond)

		neighbor.BFD = testBFDConfig()
		require.NoError(t, router.UpdateNeighbor(context.Background(), neighbor))
		requireBFDState(t, router, neighbor.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)

		neighbor.BFD = nil
		require.NoError(t, router.UpdateNeighbor(context.Background(), neighbor))
		require.Eventually(t, func() bool {
			_, found := getBFDState(router, neighbor.Address)
			return !found
		}, 3*time.Second, 25*time.Millisecond)
	})

	t.Run("BFD expiry resets and recovery restores the BGP session", func(t *testing.T) {
		peer := newTestBFDPeer(t, "127.0.0.2")
		localPort, remotePort := freeTCPPorts(t)
		localRouter := newTestRouter(t, types.ServerParameters{
			Global: types.BGPGlobal{
				ASN:        65000,
				RouterID:   "127.0.0.1",
				ListenPort: localPort,
			},
		})
		remoteRouter := newTestRouter(t, types.ServerParameters{
			Global: types.BGPGlobal{
				ASN:        65001,
				RouterID:   "127.0.0.2",
				ListenPort: remotePort,
			},
		})
		localNeighbor := testBFDNeighbor("127.0.0.2")
		localNeighbor.Timers = testBGPTimers()
		localNeighbor.Transport = &types.NeighborTransport{
			LocalAddress: "127.0.0.1",
			RemotePort:   uint32(remotePort),
		}
		remoteNeighbor := &types.Neighbor{
			Address: netip.MustParseAddr("127.0.0.1"),
			ASN:     65000,
			Timers:  testBGPTimers(),
			Transport: &types.NeighborTransport{
				LocalAddress: "127.0.0.2",
				RemotePort:   uint32(localPort),
			},
		}
		notificationReceived := make(chan *apiutil.WatchEventMessage_PeerEvent, 1)
		watchContext, cancelWatch := context.WithCancel(context.Background())
		t.Cleanup(cancelWatch)
		require.NoError(t, remoteRouter.server.WatchEvent(
			watchContext,
			server.WatchEventMessageCallbacks{
				OnPeerUpdate: func(event *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
					if event.Peer.State.DisconnectReason == gobgpapi.PeerState_DISCONNECT_REASON_NOTIFICATION_RECEIVED {
						select {
						case notificationReceived <- event:
						default:
						}
					}
				},
			},
			server.WatchPeer(),
		))

		require.NoError(t, localRouter.AddNeighbor(context.Background(), localNeighbor))
		require.NoError(t, remoteRouter.AddNeighbor(context.Background(), remoteNeighbor))
		requireBFDState(t, localRouter, localNeighbor.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)
		requirePeerSessionState(t, localRouter, types.SessionEstablished)

		peer.SetResponding(false)
		requireBFDState(t, localRouter, localNeighbor.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_DOWN)
		select {
		case event := <-notificationReceived:
			require.Contains(t, event.Peer.State.DisconnectMessage, "notification-received")
			require.Contains(t, event.Peer.State.DisconnectMessage, "code 6(cease)")
			require.Contains(t, event.Peer.State.DisconnectMessage, "subcode 4(administrative reset)")
		case <-time.After(3 * time.Second):
			t.Fatal("remote BGP peer did not receive the reset notification after BFD expired")
		}

		peer.SetResponding(true)
		requireBFDState(t, localRouter, localNeighbor.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)
		requirePeerSessionState(t, localRouter, types.SessionEstablished)
		requirePeerSessionState(t, remoteRouter, types.SessionEstablished)
	})

	t.Run("last BFD peer removal releases the listener for another server", func(t *testing.T) {
		peerA := newTestBFDPeer(t, "127.0.0.2")
		routerA := newTestBFDRouter(t, "127.0.0.1")
		neighborA := testBFDNeighbor("127.0.0.2")

		require.NoError(t, routerA.AddNeighbor(context.Background(), neighborA))
		requireBFDState(t, routerA, neighborA.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)
		peerA.Stop()
		probe, err := probeBFDListener()
		if probe != nil {
			_ = probe.Close()
		}
		require.Error(t, err)

		neighborA.BFD = nil
		require.NoError(t, routerA.UpdateNeighbor(context.Background(), neighborA))
		require.Eventually(t, func() bool {
			_, found := getBFDState(routerA, neighborA.Address)
			return !found
		}, 3*time.Second, 25*time.Millisecond)
		require.Eventually(t, func() bool {
			listener, err := probeBFDListener()
			if err != nil {
				return false
			}
			_ = listener.Close()
			return true
		}, 4*time.Second, 25*time.Millisecond)

		newTestBFDPeer(t, "127.0.0.3")
		routerB := newTestBFDRouter(t, "127.0.0.4")
		neighborB := testBFDNeighbor("127.0.0.3")
		require.NoError(t, routerB.AddNeighbor(context.Background(), neighborB))
		requireBFDState(t, routerB, neighborB.Address, gobgpapi.BfdSessionState_BFD_SESSION_STATE_UP)
	})
}

func probeBFDListener() (net.PacketConn, error) {
	return net.ListenPacket("udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(testBFDPort)))
}

func newTestBFDRouter(t *testing.T, routerID string) *GoBGPServer {
	t.Helper()

	return newTestRouter(t, types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        65000,
			RouterID:   routerID,
			ListenPort: -1,
		},
	})
}

func newTestRouter(t *testing.T, params types.ServerParameters) *GoBGPServer {
	t.Helper()

	router, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), params)
	require.NoError(t, err)

	server := router.(*GoBGPServer)
	t.Cleanup(func() {
		server.Stop(context.Background(), types.StopRequest{FullDestroy: true})
	})
	return server
}

func freeTCPPorts(t *testing.T) (int32, int32) {
	t.Helper()

	listenerA, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	listenerB, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	portA := listenerA.Addr().(*net.TCPAddr).Port
	portB := listenerB.Addr().(*net.TCPAddr).Port
	require.NoError(t, listenerA.Close())
	require.NoError(t, listenerB.Close())
	return int32(portA), int32(portB)
}

func testBFDNeighbor(address string) *types.Neighbor {
	return &types.Neighbor{
		Address: netip.MustParseAddr(address),
		ASN:     65001,
		BFD:     testBFDConfig(),
	}
}

func testBFDConfig() *types.NeighborBFD {
	return &types.NeighborBFD{
		DesiredMinTxInterval:  testBFDInterval,
		RequiredMinRxInterval: testBFDInterval,
		DetectionMultiplier:   testBFDMultiplier,
	}
}

func testBGPTimers() *types.NeighborTimers {
	return &types.NeighborTimers{
		ConnectRetry:      3,
		HoldTime:          9,
		KeepaliveInterval: 3,
	}
}

func getBFDState(router *GoBGPServer, address netip.Addr) (*gobgpapi.BfdPeerState, bool) {
	var result *gobgpapi.BfdPeerState
	router.server.ListBfdPeer(context.Background(), func(peerAddress string, state *gobgpapi.BfdPeerState) {
		if peerAddress == address.String() {
			result = state
		}
	})
	return result, result != nil
}

func requireBFDState(t *testing.T, router *GoBGPServer, address netip.Addr, expected gobgpapi.BfdSessionState) {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		state, found := getBFDState(router, address)
		require.True(collect, found)
		if found {
			require.Equal(collect, expected, state.SessionState)
		}
	}, 8*time.Second, 25*time.Millisecond)
}

func getPeerSessionState(router *GoBGPServer) (types.SessionState, error) {
	state, err := router.GetPeerState(context.Background(), &types.GetPeerStateRequest{})
	if err != nil {
		return types.SessionUnknown, err
	}
	if len(state.Peers) != 1 {
		return types.SessionUnknown, fmt.Errorf("expected one BGP peer, got %d", len(state.Peers))
	}
	return state.Peers[0].SessionState, nil
}

func requirePeerSessionState(t *testing.T, router *GoBGPServer, expected types.SessionState) {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		state, err := getPeerSessionState(router)
		require.NoError(collect, err)
		require.Equal(collect, expected, state)
	}, 30*time.Second, 25*time.Millisecond)
}

func newTestBFDPeer(t *testing.T, address string) *testutils.BFDPeer {
	return testutils.NewBFDPeer(t, address)
}
