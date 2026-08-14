// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/fake"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	unnumberedIface = "eth0"
)

var unnumberedPeerAddr = netip.MustParseAddr("fe80::1%eth0")

func unnumberedInstanceConfig(peers ...v2.CiliumBGPNodePeer) *v2.CiliumBGPNodeInstance {
	return &v2.CiliumBGPNodeInstance{
		Name:     "fake-instance",
		LocalASN: ptr.To[int64](65001),
		Peers:    peers,
	}
}

// peerIface returns the interface an unnumbered peer is configured with, from either
// spelling: PeerInterface, or the autoDiscovery Unnumbered configuration it is derived
// from. Stands in for what the DefaultGatewayReconciler and the neighbor reconciler do.
func peerIface(peer v2.CiliumBGPNodePeer) string {
	if iface := ptr.Deref(peer.PeerInterface, ""); iface != "" {
		return iface
	}
	if peer.AutoDiscovery != nil && peer.AutoDiscovery.Unnumbered != nil {
		return peer.AutoDiscovery.Unnumbered.Interface
	}
	return ""
}

// TestResolvedPeerAddresses ensures the manager only reports the addresses the router
// resolved for peers configured without one.
func TestResolvedPeerAddresses(t *testing.T) {
	unnumberedPeer := v2.CiliumBGPNodePeer{
		Name:          "unnumbered-peer",
		PeerASN:       ptr.To[int64](65002),
		PeerInterface: ptr.To(unnumberedIface),
	}
	numberedPeer := v2.CiliumBGPNodePeer{
		Name:        "numbered-peer",
		PeerASN:     ptr.To[int64](65002),
		PeerAddress: ptr.To("10.0.0.1"),
	}
	// How a peer actually reaches this code when the user configures autoDiscovery
	// mode Unnumbered: only the AutoDiscovery interface is set. PeerInterface is
	// derived from it later, by a reconciler that runs after this snapshot is taken.
	autoDiscoveryPeer := v2.CiliumBGPNodePeer{
		Name:    "autodiscovery-unnumbered-peer",
		PeerASN: ptr.To[int64](65002),
		AutoDiscovery: &v2.BGPAutoDiscovery{
			Mode:       v2.BGPUnnumberedMode,
			Unnumbered: &v2.BGPUnnumbered{Interface: unnumberedIface},
		},
	}
	defaultGatewayPeer := v2.CiliumBGPNodePeer{
		Name:    "default-gateway-peer",
		PeerASN: ptr.To[int64](65002),
		AutoDiscovery: &v2.BGPAutoDiscovery{
			Mode:           v2.BGPDefaultGatewayMode,
			DefaultGateway: &v2.DefaultGateway{AddressFamily: "ipv4"},
		},
	}

	tests := []struct {
		name     string
		peers    []v2.CiliumBGPNodePeer
		resolve  bool
		expected map[string]netip.Addr
	}{
		{
			name:     "no unnumbered peer does not query the router",
			peers:    []v2.CiliumBGPNodePeer{numberedPeer},
			expected: nil,
		},
		{
			name:     "unnumbered peer not resolved by the router yet",
			peers:    []v2.CiliumBGPNodePeer{unnumberedPeer},
			expected: map[string]netip.Addr{},
		},
		{
			name:     "unnumbered peer resolved by the router",
			peers:    []v2.CiliumBGPNodePeer{unnumberedPeer, numberedPeer},
			resolve:  true,
			expected: map[string]netip.Addr{unnumberedPeer.Name: unnumberedPeerAddr},
		},
		{
			// Regression: the peer is unnumbered by way of autoDiscovery only, so
			// PeerInterface is not set yet at this point. Keying off PeerInterface
			// alone left it unresolved and nothing was ever advertised to it.
			name:     "autoDiscovery unnumbered peer resolved by the router",
			peers:    []v2.CiliumBGPNodePeer{autoDiscoveryPeer, numberedPeer},
			resolve:  true,
			expected: map[string]netip.Addr{autoDiscoveryPeer.Name: unnumberedPeerAddr},
		},
		{
			name:     "autoDiscovery unnumbered peer not resolved by the router yet",
			peers:    []v2.CiliumBGPNodePeer{autoDiscoveryPeer},
			expected: map[string]netip.Addr{},
		},
		{
			name:     "autoDiscovery default gateway peer is not unnumbered",
			peers:    []v2.CiliumBGPNodePeer{defaultGatewayPeer},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := instance.NewFakeBGPInstance()
			router := i.Router.(*fake.FakeRouter)
			conf := unnumberedInstanceConfig(tt.peers...)

			for _, peer := range conf.Peers {
				require.NoError(t, router.AddNeighbor(context.Background(), &types.Neighbor{
					Name:      peer.Name,
					Interface: peerIface(peer),
				}))
			}
			if tt.resolve {
				router.DiscoverPeerAddress(unnumberedIface, unnumberedPeerAddr)
			}

			m := &BGPRouterManager{logger: hivetest.Logger(t)}
			require.Equal(t, tt.expected, m.resolvedPeerAddresses(context.Background(), i, conf))
		})
	}
}

// TestReconcileSignalsResolvedUnnumberedPeer ensures another reconciliation round is
// requested once the router resolved the address of an unnumbered peer, as the peer is
// added by the neighbor reconciler only after the reconcilers keyed on the peer address
// have already run.
func TestReconcileSignalsResolvedUnnumberedPeer(t *testing.T) {
	db := statedb.New()
	reconcileErrTbl, err := tables.NewBGPReconcileErrorTable(db)
	require.NoError(t, err)

	i := instance.NewFakeBGPInstance()
	router := i.Router.(*fake.FakeRouter)
	conf := unnumberedInstanceConfig(v2.CiliumBGPNodePeer{
		Name:          "unnumbered-peer",
		PeerASN:       ptr.To[int64](65002),
		PeerInterface: ptr.To(unnumberedIface),
	})

	// Stands in for the neighbor reconciler: adds the peer, which is the point the
	// router resolves its address.
	var seenAddresses []map[string]netip.Addr
	addPeer := reconciler.NewFakeReconciler(reconciler.FakeReconcilerParams{
		Name: "add-unnumbered-peer",
		ReconcilerFunc: func(ctx context.Context, params reconciler.ReconcileParams) error {
			seenAddresses = append(seenAddresses, params.ResolvedPeerAddresses)
			if err := router.AddNeighbor(ctx, &types.Neighbor{
				Name:      params.DesiredConfig.Peers[0].Name,
				Interface: unnumberedIface,
			}); err != nil {
				return err
			}
			router.DiscoverPeerAddress(unnumberedIface, unnumberedPeerAddr)
			return nil
		},
	})

	sig := signaler.NewBGPCPSignaler()
	m := &BGPRouterManager{
		logger:              hivetest.Logger(t),
		signaler:            sig,
		BGPInstances:        LocalInstanceMap{i.Name: i},
		ConfigReconcilers:   []reconciler.ConfigReconciler{addPeer},
		DB:                  db,
		ReconcileErrorTable: reconcileErrTbl,
		metrics:             NewBGPManagerMetrics(),
		running:             true,
	}
	node := &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}

	// First round: the peer does not exist yet, so it has no address and another
	// round is requested.
	require.NoError(t, m.reconcileBGPConfig(context.Background(), i, conf, node))
	require.Equal(t, []map[string]netip.Addr{{}}, seenAddresses)
	require.Len(t, sig.Sig, 1, "reconciliation round should have been requested")
	<-sig.Sig

	// Second round: the reconcilers see the resolved address and nothing changes, so
	// no further round is requested.
	require.NoError(t, m.reconcileBGPConfig(context.Background(), i, conf, node))
	require.Equal(t, map[string]netip.Addr{"unnumbered-peer": unnumberedPeerAddr}, seenAddresses[1])
	require.Empty(t, sig.Sig, "reconciliation should have converged")
}
