// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v4/api"

	"github.com/cilium/cilium/pkg/bgp/types"
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
	oldPeer, err := g.getExistingPeer(ctx, n.Address, n.Interface, n.ASN)
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

	// perform full / soft peer reset if necessary. Reset by the address gobgp
	// identifies the peer with, which for an unnumbered peer is the link-local it
	// resolved, not the configured one. An unresolved peer has no session to reset.
	oldAddr := resolvedPeerAddress(oldPeer)
	if (needsHardReset || updateRes.NeedsSoftResetIn) && oldAddr.IsValid() {
		resetReq := &gobgp.ResetPeerRequest{
			Address:       oldAddr.String(),
			Communication: "Peer configuration changed",
		}
		if !needsHardReset {
			resetReq.Soft = true
			resetReq.Direction = gobgp.ResetPeerRequest_DIRECTION_IN
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
// An unnumbered peer has no configured address, so it is matched by the interface it peers
// on instead. If no such peer can be found, error is returned.
func (g *GoBGPServer) getExistingPeer(ctx context.Context, peerAddr netip.Addr, peerIface string, peerASN uint32) (*gobgp.Peer, error) {
	// GoBGP accepts either the neighbor address or the neighbor interface as the
	// ListPeer filter.
	key := peerIface
	if peerAddr.IsValid() {
		key = peerAddr.String()
	}

	var res *gobgp.Peer
	fn := func(peer *gobgp.Peer) {
		if peer.Conf == nil || peer.Conf.PeerAsn != peerASN {
			return
		}
		if peerAddr.IsValid() {
			if pIP, err := netip.ParseAddr(peer.Conf.NeighborAddress); err == nil && pIP == peerAddr {
				res = peer
			}
			return
		}
		if peerIface != "" && peer.Conf.NeighborInterface == peerIface {
			res = peer
		}
	}

	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{Address: key}, fn)
	if err != nil {
		return nil, fmt.Errorf("listing peers failed: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("could not find existing peer with ASN: %d and IP: %s", peerASN, key)
	}
	return res, nil
}

// RemoveNeighbor will remove the peer from the gobgp.BgpServer,
// disconnecting the BGP peering connection.
func (g *GoBGPServer) RemoveNeighbor(ctx context.Context, n *types.Neighbor) error {
	peerReq := &gobgp.DeletePeerRequest{}
	switch {
	case n.Address.IsValid():
		peerReq.Address = n.Address.String()
	default:
		// An unnumbered peer has no configured address, and gobgp's DeletePeer
		// cannot resolve the interface on its own: it builds a neighbor carrying
		// only NeighborInterface and then asks it for an address, which fails with
		// "NeighborAddress is not configured" (and with an empty address string,
		// gobgp v4 parses it with netip.MustParseAddr and panics). Look the running
		// peer up by interface and delete it by the link-local gobgp resolved for
		// it via ND, which is what it is keyed by.
		//
		// This matters as soon as an unnumbered peer's interface changes - it moves
		// with the default route under autoDiscovery mode Unnumbered - as the peer
		// is then removed and re-added under the new interface.
		existing, err := g.getExistingPeer(ctx, netip.Addr{}, n.Interface, n.ASN)
		if err != nil {
			return fmt.Errorf("failed to get existing peer on interface %s: %w", n.Interface, err)
		}
		if addr := resolvedPeerAddress(existing); addr.IsValid() {
			peerReq.Address = addr.String()
		} else {
			peerReq.Interface = n.Interface
		}
	}
	if err := g.server.DeletePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.Address, n.ASN, err)
	}
	return nil
}

// ResetNeighbor resets BGP peering with the provided neighbor address.
func (g *GoBGPServer) ResetNeighbor(ctx context.Context, r types.ResetNeighborRequest) error {
	resetReq := &gobgp.ResetPeerRequest{
		Address:       r.PeerAddress.String(),
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

// ResetAllNeighbors resets BGP peering with all configured neighbors.
func (g *GoBGPServer) ResetAllNeighbors(ctx context.Context, r types.ResetAllNeighborsRequest) error {
	// Get all peers first. Unnumbered peers are reset by the link-local gobgp
	// resolved for them; skip any peer that is not resolved yet, as it has no
	// session to reset and gobgp would reject the request for all of them.
	var peerAddresses []string
	fn := func(peer *gobgp.Peer) {
		if peer == nil {
			return
		}
		if addr := resolvedPeerAddress(peer); addr.IsValid() {
			peerAddresses = append(peerAddresses, addr.String())
		}
	}

	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{}, fn)
	if err != nil {
		return fmt.Errorf("failed to list peers: %w", err)
	}

	// Reset each peer
	for _, peerAddr := range peerAddresses {
		resetReq := &gobgp.ResetPeerRequest{
			Address:       peerAddr,
			Communication: r.AdminCommunication,
		}
		if r.Soft {
			resetReq.Soft = true
			resetReq.Direction = toGoBGPSoftResetDirection(r.SoftResetDirection)
		}
		if err := g.server.ResetPeer(ctx, resetReq); err != nil {
			return fmt.Errorf("failed while resetting peer %s: %w", peerAddr, err)
		}
	}

	return nil
}
