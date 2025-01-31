// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// AddNeighbor will add the CiliumBGPNeighbor to the gobgp.BgpServer, creating
// a BGP peering connection.
func (g *GoBGPServer) AddNeighbor(ctx context.Context, n *types.Neighbor) error {
	peerReq := &gobgp.AddPeerRequest{
		Peer: ToGoBGPPeer(n, nil, n.Address.Is4()),
	}
	if err := g.server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %s with ASN %d: %w", n.Address, n.ASN, err)
	}
	return nil
}

// UpdateNeighbor will update the existing CiliumBGPNeighbor in the gobgp.BgpServer.
func (g *GoBGPServer) UpdateNeighbor(ctx context.Context, n *types.Neighbor) error {
	oldPeer, err := g.getExistingPeer(ctx, n.Address, n.ASN)
	if err != nil {
		return fmt.Errorf("failed to get existing peer: %w", err)
	}

	newPeer := ToGoBGPPeer(n, oldPeer, n.Address.Is4())

	needsHardReset := g.needsHardReset(oldPeer, newPeer)

	// update peer config
	peerReq := &gobgp.UpdatePeerRequest{
		Peer: ToGoBGPPeer(n, oldPeer, n.Address.Is4()),
	}

	updateRes, err := g.server.UpdatePeer(ctx, peerReq)
	if err != nil {
		return fmt.Errorf("failed while updating peer %v:%v with ASN %v: %w", oldPeer.Conf.NeighborAddress, oldPeer.Transport.RemotePort, oldPeer.Conf.PeerAsn, err)
	}

	// perform full / soft peer reset if necessary
	if needsHardReset || updateRes.NeedsSoftResetIn {
		resetReq := &gobgp.ResetPeerRequest{
			Address:       oldPeer.Conf.NeighborAddress,
			Communication: "Peer configuration changed",
		}
		if !needsHardReset {
			resetReq.Soft = true
			resetReq.Direction = gobgp.ResetPeerRequest_IN
		}
		if err = g.server.ResetPeer(ctx, resetReq); err != nil {
			return fmt.Errorf("failed while resetting peer %v:%v in ASN %v: %w", oldPeer.Conf.NeighborAddress, oldPeer.Transport.RemotePort, oldPeer.Conf.PeerAsn, err)
		}
	}

	return nil
}

func (g *GoBGPServer) needsHardReset(oldPeer, newPeer *gobgp.Peer) bool {
	// In some cases, we want to perform full session reset on update even if GoBGP would not perform it.
	// An example of that is updating timer parameters that are negotiated during the session setup.
	// As we provide declarative API (CRD), we want this config to be applied on existing sessions
	// immediately, therefore we need full session reset.
	if oldPeer == nil {
		return false
	}
	if (oldPeer.Timers != nil && newPeer.Timers != nil) &&
		(oldPeer.Timers.Config.HoldTime != newPeer.Timers.Config.HoldTime ||
			oldPeer.Timers.Config.KeepaliveInterval != newPeer.Timers.Config.KeepaliveInterval) {
		return true
	}
	return false
}

// getExistingPeer returns the existing GoBGP Peer matching provided peer address and ASN.
// If no such peer can be found, error is returned.
func (g *GoBGPServer) getExistingPeer(ctx context.Context, peerAddr netip.Addr, peerASN uint32) (*gobgp.Peer, error) {
	var res *gobgp.Peer
	fn := func(peer *gobgp.Peer) {
		pIP, err := netip.ParseAddr(peer.Conf.NeighborAddress)
		if err == nil && pIP == peerAddr && peer.Conf.PeerAsn == peerASN {
			res = peer
		}
	}

	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{Address: peerAddr.String()}, fn)
	if err != nil {
		return nil, fmt.Errorf("listing peers failed: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("could not find existing peer with ASN: %d and IP: %s", peerASN, peerAddr)
	}
	return res, nil
}

// RemoveNeighbor will remove the peer from the gobgp.BgpServer,
// disconnecting the BGP peering connection.
func (g *GoBGPServer) RemoveNeighbor(ctx context.Context, n *types.Neighbor) error {
	peerReq := &gobgp.DeletePeerRequest{
		Address: n.Address.String(),
	}
	if err := g.server.DeletePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.Address, n.ASN, err)
	}
	return nil
}

// ResetNeighbor resets BGP peering with the provided neighbor address.
func (g *GoBGPServer) ResetNeighbor(ctx context.Context, r types.ResetNeighborRequest) error {
	// for this request we need a peer address without prefix
	peerAddr := r.PeerAddress
	if p, err := netip.ParsePrefix(r.PeerAddress); err == nil {
		peerAddr = p.Addr().String()
	}

	resetReq := &gobgp.ResetPeerRequest{
		Address:       peerAddr,
		Communication: r.AdminCommunication,
	}
	if r.Soft {
		resetReq.Soft = true
		resetReq.Direction = toGoBGPSoftResetDirection(r.SoftResetDirection)
	}
	if err := g.server.ResetPeer(ctx, resetReq); err != nil {
		return fmt.Errorf("failed while resetting peer %s: %w", r.PeerAddress, err)
	}
	return nil
}
