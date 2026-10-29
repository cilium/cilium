// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	gobgp "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/types"
)

var (
	tcpAOKey1 = types.TCPAOKey{
		SendID:    1,
		ReceiveID: 1,
		Algorithm: types.TCPAOAlgorithmHMACSHA1_96,
		MasterKey: []byte("master-key-1"),
	}
	tcpAOKey2 = types.TCPAOKey{
		SendID:    2,
		ReceiveID: 2,
		Algorithm: types.TCPAOAlgorithmHMACSHA256_128,
		MasterKey: []byte("master-key-2"),
	}
	tcpAOKey3 = types.TCPAOKey{
		SendID:            3,
		ReceiveID:         3,
		Algorithm:         types.TCPAOAlgorithmAES128CMAC_96,
		ExcludeTCPOptions: true,
		MasterKey:         []byte("master-key-3"),
	}
)

func TestPlanTCPAOKeychainUpdate(t *testing.T) {
	key2Changed := tcpAOKey2
	key2Changed.MasterKey = []byte("master-key-2-changed")
	key1Changed := tcpAOKey1
	key1Changed.ReceiveID = 11

	var table = []struct {
		name     string
		current  *types.NeighborTCPAO
		desired  *types.NeighborTCPAO
		inUse    []uint8
		expected *tcpAOKeychainUpdate
		reset    bool
	}{
		{
			name:     "no change",
			current:  &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
			desired:  &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
			expected: &tcpAOKeychainUpdate{},
		},
		{
			name:     "send key change only",
			current:  &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired:  &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			expected: &tcpAOKeychainUpdate{},
		},
		{
			name:    "add key",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
			desired: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			expected: &tcpAOKeychainUpdate{
				addKeys: []types.TCPAOKey{tcpAOKey2},
			},
		},
		{
			name:    "remove key",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
			expected: &tcpAOKeychainUpdate{
				deleteKeys: []types.TCPAOKey{tcpAOKey2},
			},
		},
		{
			// the old send key is still in use on the socket until the peer switches as well
			name:    "rotate in one step: add new key, move send to it, remove old key requires reset",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2}},
			reset:   true,
		},
		{
			name:    "rotate step 1: add new key and move send to it",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			inUse:   []uint8{1},
			expected: &tcpAOKeychainUpdate{
				addKeys: []types.TCPAOKey{tcpAOKey2},
			},
		},
		{
			name:    "rotate step 2: remove old key once both sides switched",
			current: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2}},
			inUse:   []uint8{2},
			expected: &tcpAOKeychainUpdate{
				deleteKeys: []types.TCPAOKey{tcpAOKey1},
			},
		},
		{
			name:    "change content of a non-send key",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, key2Changed}},
			expected: &tcpAOKeychainUpdate{
				addKeys:           []types.TCPAOKey{key2Changed},
				deleteChangedKeys: []types.TCPAOKey{tcpAOKey2},
			},
		},
		{
			name:    "change content of the send key requires reset",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{key1Changed, tcpAOKey2}},
			reset:   true,
		},
		{
			name:    "change content of the send key while moving send to another key requires reset",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{key1Changed, tcpAOKey2}},
			reset:   true,
		},
		{
			// the preferred send key was moved to key 2, but the peer still requests key 1 (RNextKeyID)
			name:    "change content of a non-send key which is still in use on the socket requires reset",
			current: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{key1Changed, tcpAOKey2}},
			inUse:   []uint8{1, 2},
			reset:   true,
		},
		{
			name:    "remove a non-send key which is still in use on the socket requires reset",
			current: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2}},
			inUse:   []uint8{1, 2},
			reset:   true,
		},
		{
			name:    "remove the preferred send key while moving send to another key requires reset",
			current: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2}},
			inUse:   []uint8{1},
			reset:   true,
		},
		{
			name:    "remove a non-send key which is not in use on the socket is hitless",
			current: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}},
			desired: &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2}},
			inUse:   []uint8{2},
			expected: &tcpAOKeychainUpdate{
				deleteKeys: []types.TCPAOKey{tcpAOKey1},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			update, err := planTCPAOKeychainUpdate(tt.current, tt.desired, tt.inUse)
			if tt.reset {
				require.ErrorIs(t, err, errTCPAOResetRequired)
				require.Nil(t, update)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, update)
			require.Equal(t, tt.expected.empty(), update.empty())
		})
	}
}

func TestTCPAOKeychainUpdateAfterAddPhase(t *testing.T) {
	key2Changed := tcpAOKey2
	key2Changed.MasterKey = []byte("master-key-2-changed")

	key4 := types.TCPAOKey{SendID: 4, ReceiveID: 4, Algorithm: types.TCPAOAlgorithmHMACSHA1_96, MasterKey: []byte("master-key-4")}

	current := &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2, key4}}
	desired := &types.NeighborTCPAO{SendID: 3, Keys: []types.TCPAOKey{tcpAOKey1, key2Changed, tcpAOKey3}}

	update, err := planTCPAOKeychainUpdate(current, desired, nil)
	require.NoError(t, err)
	require.Equal(t, &tcpAOKeychainUpdate{
		addKeys:           []types.TCPAOKey{key2Changed, tcpAOKey3},
		deleteChangedKeys: []types.TCPAOKey{tcpAOKey2},
		deleteKeys:        []types.TCPAOKey{key4},
	}, update)

	// after the add phase: changed key replaced, new key added, removed key still present, send ID unchanged
	require.Equal(t, &types.NeighborTCPAO{
		SendID: 1,
		Keys:   []types.TCPAOKey{tcpAOKey1, key4, key2Changed, tcpAOKey3},
	}, update.afterAddPhase(current))
}

func TestTCPAOKeysInUse(t *testing.T) {
	require.Empty(t, tcpAOKeysInUse(nil))
	require.Empty(t, tcpAOKeysInUse(&gobgp.Peer{}))
	require.Equal(t, []uint8{1, 3}, tcpAOKeysInUse(&gobgp.Peer{
		State: &gobgp.PeerState{
			TcpAoState: &gobgp.TcpAoPeerState{
				Keys: []*gobgp.TcpAoKeyState{
					{SendId: 1, ReceiveId: 1, Current: true},
					{SendId: 2, ReceiveId: 2},
					{SendId: 3, ReceiveId: 3, ReceiveNext: true},
				},
			},
		},
	}))
}

func TestValidateNeighborAuth(t *testing.T) {
	require.NoError(t, validateNeighborAuth(&types.Neighbor{}))
	require.NoError(t, validateNeighborAuth(&types.Neighbor{AuthPassword: "pw"}))
	require.NoError(t, validateNeighborAuth(&types.Neighbor{
		TCPAO: &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
	}))
	require.Error(t, validateNeighborAuth(&types.Neighbor{
		AuthPassword: "pw",
		TCPAO:        &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}},
	}))
	require.Error(t, validateNeighborAuth(&types.Neighbor{
		TCPAO: &types.NeighborTCPAO{SendID: 9, Keys: []types.TCPAOKey{tcpAOKey1}},
	}))
}

// TestTCPAONeighborLifecycle exercises the TCP-AO keychain management of the adapter
// against an in-process GoBGP server: add / hitless update / reset update / disable / remove.
func TestTCPAONeighborLifecycle(t *testing.T) {
	ctx := context.Background()
	srv, err := NewGoBGPServer(ctx, hivetest.Logger(t), testServerParameters)
	require.NoError(t, err)
	t.Cleanup(func() {
		srv.Stop(ctx, types.StopRequest{FullDestroy: true})
	})
	router := srv.(*GoBGPServer)

	peerAddr := netip.MustParseAddr("192.168.0.1")
	keychainName := tcpAOKeychainName(peerAddr)

	newNeighbor := func(tcpAO *types.NeighborTCPAO) *types.Neighbor {
		return &types.Neighbor{
			Name:    "tcp-ao-peer",
			ASN:     64125,
			Address: peerAddr,
			Transport: &types.NeighborTransport{
				RemotePort: 179,
			},
			TCPAO: tcpAO,
		}
	}

	listKeychain := func() *gobgp.TcpAoKeychain {
		var res *gobgp.TcpAoKeychain
		err := router.server.ListTcpAoKeychain(ctx, &gobgp.ListTcpAoKeychainRequest{Name: keychainName}, func(kc *gobgp.TcpAoKeychain) {
			res = kc
		})
		require.NoError(t, err)
		return res
	}

	keychainSendIDs := func() []uint32 {
		kc := listKeychain()
		if kc == nil {
			return nil
		}
		ids := make([]uint32, 0, len(kc.Keys))
		for _, k := range kc.Keys {
			ids = append(ids, k.SendId)
		}
		return ids
	}

	getPeer := func() *gobgp.Peer {
		var res *gobgp.Peer
		err := router.server.ListPeer(ctx, &gobgp.ListPeerRequest{Address: peerAddr.String()}, func(p *gobgp.Peer) {
			res = p
		})
		require.NoError(t, err)
		require.NotNil(t, res)
		return res
	}

	getPeerState := func() types.PeerState {
		resp, err := srv.GetPeerState(ctx, &types.GetPeerStateRequest{})
		require.NoError(t, err)
		require.Len(t, resp.Peers, 1)
		return resp.Peers[0]
	}

	t.Run("add neighbor with both TCP-AO and MD5 password fails", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		n.AuthPassword = "password"
		require.Error(t, srv.AddNeighbor(ctx, n))
		require.Nil(t, listKeychain())
	})

	t.Run("add neighbor with invalid TCP-AO fails and leaves no keychain", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 42, Keys: []types.TCPAOKey{tcpAOKey1}})
		require.Error(t, srv.AddNeighbor(ctx, n))
		require.Nil(t, listKeychain())
	})

	t.Run("add neighbor with TCP-AO", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		require.NoError(t, srv.AddNeighbor(ctx, n))

		require.Equal(t, []uint32{1}, keychainSendIDs())
		peer := getPeer()
		require.NotNil(t, peer.TcpAo)
		require.Equal(t, keychainName, peer.TcpAo.Keychain)
		require.Equal(t, uint32(1), peer.TcpAo.SendId)

		state := getPeerState()
		require.True(t, state.TCPAOEnabled)
		require.False(t, state.TCPPasswordEnabled)
		require.NotNil(t, state.TCPAO)
		require.Equal(t, uint8(1), state.TCPAO.SendID)

		// the adapter keeps its own copy of the keychain
		require.Equal(t, n.TCPAO, router.getTCPAOKeychain(peerAddr))
	})

	t.Run("update neighbor without TCP-AO change", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		n.Timers = &types.NeighborTimers{ConnectRetry: 10, HoldTime: 30, KeepaliveInterval: 10}
		require.NoError(t, srv.UpdateNeighbor(ctx, n))

		require.Equal(t, []uint32{1}, keychainSendIDs())
		require.Equal(t, uint32(1), getPeer().TcpAo.SendId)
	})

	t.Run("interrupted hitless update can be retried", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}})

		// simulate an update which failed after the new keys were installed, but before the peer was updated
		upd, err := router.prepareTCPAOUpdate(ctx, n, getPeer())
		require.NoError(t, err)
		require.NotNil(t, upd.keychainUpdate)
		require.Equal(t, []uint32{1, 2}, keychainSendIDs())
		require.Equal(t, uint32(1), getPeer().TcpAo.SendId)
		require.Equal(t, &types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}}, router.getTCPAOKeychain(peerAddr))

		// retrying the update must not try to install the keys again
		require.NoError(t, srv.UpdateNeighbor(ctx, n))
		require.Equal(t, []uint32{1, 2}, keychainSendIDs())
		require.Equal(t, uint32(2), getPeer().TcpAo.SendId)
		require.Equal(t, n.TCPAO, router.getTCPAOKeychain(peerAddr))
	})

	t.Run("hitless update: add key and rotate send key", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2}})
		require.NoError(t, srv.UpdateNeighbor(ctx, n))

		require.Equal(t, []uint32{1, 2}, keychainSendIDs())
		peer := getPeer()
		require.Equal(t, keychainName, peer.TcpAo.Keychain)
		require.Equal(t, uint32(2), peer.TcpAo.SendId)
		require.Equal(t, uint8(2), getPeerState().TCPAO.SendID)
		require.Equal(t, n.TCPAO, router.getTCPAOKeychain(peerAddr))
	})

	t.Run("hitless update: remove old key, change non-send key", func(t *testing.T) {
		key3 := tcpAOKey3
		n := newNeighbor(&types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2, key3}})
		require.NoError(t, srv.UpdateNeighbor(ctx, n))
		require.Equal(t, []uint32{2, 3}, keychainSendIDs())

		key3.MasterKey = []byte("master-key-3-rotated")
		n = newNeighbor(&types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey2, key3}})
		require.NoError(t, srv.UpdateNeighbor(ctx, n))
		require.Equal(t, []uint32{2, 3}, keychainSendIDs())
		require.Equal(t, uint32(2), getPeer().TcpAo.SendId)
		require.Equal(t, n.TCPAO, router.getTCPAOKeychain(peerAddr))
	})

	t.Run("reset update: change content of the send key", func(t *testing.T) {
		key2 := tcpAOKey2
		key2.MasterKey = []byte("master-key-2-rotated")
		n := newNeighbor(&types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{key2, tcpAOKey3}})
		require.NoError(t, srv.UpdateNeighbor(ctx, n))

		require.Equal(t, []uint32{2, 3}, keychainSendIDs())
		peer := getPeer()
		require.Equal(t, keychainName, peer.TcpAo.Keychain)
		require.Equal(t, uint32(2), peer.TcpAo.SendId)
		require.Equal(t, n.TCPAO, router.getTCPAOKeychain(peerAddr))
	})

	t.Run("disable TCP-AO", func(t *testing.T) {
		n := newNeighbor(nil)
		require.NoError(t, srv.UpdateNeighbor(ctx, n))

		require.Nil(t, listKeychain())
		peer := getPeer()
		require.True(t, peer.TcpAo == nil || peer.TcpAo.Keychain == "")
		state := getPeerState()
		require.False(t, state.TCPAOEnabled)
		require.Nil(t, state.TCPAO)
		require.Nil(t, router.getTCPAOKeychain(peerAddr))
	})

	t.Run("switch to MD5 password and back to TCP-AO", func(t *testing.T) {
		n := newNeighbor(nil)
		n.AuthPassword = "password"
		require.NoError(t, srv.UpdateNeighbor(ctx, n))
		state := getPeerState()
		require.True(t, state.TCPPasswordEnabled)
		require.False(t, state.TCPAOEnabled)

		n = newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		require.NoError(t, srv.UpdateNeighbor(ctx, n))
		require.Equal(t, []uint32{1}, keychainSendIDs())
		peer := getPeer()
		require.Equal(t, keychainName, peer.TcpAo.Keychain)
		require.Empty(t, peer.Conf.AuthPassword)
		state = getPeerState()
		require.False(t, state.TCPPasswordEnabled)
		require.True(t, state.TCPAOEnabled)
	})

	t.Run("remove neighbor deletes the keychain", func(t *testing.T) {
		n := newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		require.NoError(t, srv.RemoveNeighbor(ctx, n))

		require.Nil(t, listKeychain())
		require.Nil(t, router.getTCPAOKeychain(peerAddr))
		resp, err := srv.GetPeerState(ctx, &types.GetPeerStateRequest{})
		require.NoError(t, err)
		require.Empty(t, resp.Peers)
	})

	t.Run("update of a missing neighbor adds it", func(t *testing.T) {
		// simulates a re-create (reset) update which failed after the peer was removed
		n := newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		require.NoError(t, srv.UpdateNeighbor(ctx, n))

		require.Equal(t, []uint32{1}, keychainSendIDs())
		require.Equal(t, keychainName, getPeer().TcpAo.Keychain)
		require.Equal(t, n.TCPAO, router.getTCPAOKeychain(peerAddr))

		require.NoError(t, srv.RemoveNeighbor(ctx, n))
		require.Nil(t, listKeychain())
	})

	t.Run("stale keychain is replaced on add", func(t *testing.T) {
		// simulate a keychain left over from a failed operation
		require.NoError(t, router.server.AddTcpAoKeychain(ctx, &gobgp.AddTcpAoKeychainRequest{
			Keychain: toGoBGPTCPAOKeychain(keychainName, &types.NeighborTCPAO{SendID: 3, Keys: []types.TCPAOKey{tcpAOKey3}}),
		}))
		require.Equal(t, []uint32{3}, keychainSendIDs())

		n := newNeighbor(&types.NeighborTCPAO{SendID: 1, Keys: []types.TCPAOKey{tcpAOKey1}})
		require.NoError(t, srv.AddNeighbor(ctx, n))
		require.Equal(t, []uint32{1}, keychainSendIDs())
		require.NoError(t, srv.RemoveNeighbor(ctx, n))
		require.Nil(t, listKeychain())
	})
}

func TestToGoBGPTCPAOConversions(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	tcpAO := &types.NeighborTCPAO{SendID: 2, Keys: []types.TCPAOKey{tcpAOKey1, tcpAOKey2, tcpAOKey3}}

	require.Nil(t, toGoBGPTCPAOPeerConfig(addr, nil))
	peerConf := toGoBGPTCPAOPeerConfig(addr, tcpAO)
	require.Equal(t, "cilium-fd00::1", peerConf.Keychain)
	require.Equal(t, uint32(2), peerConf.SendId)

	kc := toGoBGPTCPAOKeychain("kc", tcpAO)
	require.Equal(t, "kc", kc.Name)
	require.Len(t, kc.Keys, 3)
	require.Equal(t, gobgp.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, kc.Keys[0].Algorithm)
	require.Equal(t, gobgp.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128, kc.Keys[1].Algorithm)
	require.Equal(t, gobgp.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, kc.Keys[2].Algorithm)
	require.True(t, kc.Keys[2].ExcludeTcpOptions)
	require.Equal(t, []byte("master-key-3"), kc.Keys[2].MasterKey)
	// master keys are copied, not aliased
	require.NotSame(t, &tcpAOKey3.MasterKey[0], &kc.Keys[2].MasterKey[0])

	// state conversion
	require.Nil(t, toAgentTCPAOState(nil, nil))
	state := toAgentTCPAOState(peerConf, &gobgp.TcpAoPeerState{
		Keys: []*gobgp.TcpAoKeyState{
			{SendId: 1, ReceiveId: 1, PacketsGood: 10, PacketsBad: 1},
			{SendId: 2, ReceiveId: 2, Current: true, ReceiveNext: true, PacketsGood: 20},
		},
		PacketsKeyNotFound: 3,
		PacketsAoRequired:  4,
		PacketsDroppedIcmp: 5,
	})
	require.NotNil(t, state)
	require.Equal(t, uint8(2), state.SendID)
	require.Len(t, state.Keys, 2)
	require.Equal(t, types.PeerTCPAOKeyState{SendID: 1, ReceiveID: 1, PacketsGood: 10, PacketsBad: 1}, state.Keys[0])
	require.Equal(t, types.PeerTCPAOKeyState{SendID: 2, ReceiveID: 2, Current: true, ReceiveNext: true, PacketsGood: 20}, state.Keys[1])
	require.Equal(t, uint64(3), state.PacketsKeyNotFound)
	require.Equal(t, uint64(4), state.PacketsAORequired)
	require.Equal(t, uint64(5), state.PacketsDroppedICMP)
}
