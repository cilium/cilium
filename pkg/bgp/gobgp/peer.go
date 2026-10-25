// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v4/api"

	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// errPeerNotFound is returned by getExistingPeer when no peer matches the given address and ASN.
var errPeerNotFound = errors.New("could not find existing peer")

// AddNeighbor will add the CiliumBGPNeighbor to the gobgp.BgpServer, creating
// a BGP peering connection.
func (g *GoBGPServer) AddNeighbor(ctx context.Context, n *types.Neighbor) error {
	if err := validateNeighborAuth(n); err != nil {
		return fmt.Errorf("failed while adding peer %s with ASN %d: %w", n.Address, n.ASN, err)
	}

	// the TCP-AO keychain must exist before the peer referencing it is added
	if n.TCPAO != nil {
		if err := g.addTCPAOKeychain(ctx, n.Address, n.TCPAO); err != nil {
			return fmt.Errorf("failed while adding peer %s with ASN %d: %w", n.Address, n.ASN, err)
		}
	}

	peerReq := &gobgp.AddPeerRequest{
		Peer: ToGoBGPPeer(n, nil, n.Address.Is4()),
	}
	if err := g.server.AddPeer(ctx, peerReq); err != nil {
		if n.TCPAO != nil {
			// best-effort cleanup of the keychain created above
			if cleanupErr := g.deleteTCPAOKeychain(ctx, n.Address); cleanupErr != nil {
				g.logger.Warn("Failed to clean up TCP-AO keychain after failed peer addition",
					types.PeerLogField, n.Address,
					logfields.Error, cleanupErr,
				)
			}
		}
		return fmt.Errorf("failed while adding peer %s with ASN %d: %w", n.Address, n.ASN, err)
	}
	return nil
}

// UpdateNeighbor will update the existing CiliumBGPNeighbor in the gobgp.BgpServer.
func (g *GoBGPServer) UpdateNeighbor(ctx context.Context, n *types.Neighbor) error {
	if err := validateNeighborAuth(n); err != nil {
		return fmt.Errorf("failed while updating peer %s with ASN %d: %w", n.Address, n.ASN, err)
	}

	oldPeer, err := g.getExistingPeer(ctx, n.Address, n.ASN)
	if errors.Is(err, errPeerNotFound) {
		// The peer may have been removed by a previous update attempt which failed
		// half-way (e.g. when re-creating the peer). Add it instead of failing forever.
		g.logger.Info("Peer to update does not exist, adding it instead",
			types.PeerLogField, n.Address,
			logfields.Error, err,
		)
		return g.AddNeighbor(ctx, n)
	}
	if err != nil {
		return fmt.Errorf("failed to get existing peer: %w", err)
	}

	// apply the TCP-AO keychain changes that need to happen before the peer update
	tcpAOUpdate, err := g.prepareTCPAOUpdate(ctx, n, oldPeer)
	if err != nil {
		return fmt.Errorf("failed while updating peer %v:%v with ASN %v: %w", oldPeer.Conf.NeighborAddress, oldPeer.Transport.RemotePort, oldPeer.Conf.PeerAsn, err)
	}
	if tcpAOUpdate.resetPeer {
		// The TCP-AO change can not be applied in-place: re-create the peer, which applies
		// the whole new configuration at the cost of a session reset.
		if err := g.RemoveNeighbor(ctx, n); err != nil {
			return fmt.Errorf("failed while re-creating peer %v with ASN %v: %w", n.Address, n.ASN, err)
		}
		if err := g.AddNeighbor(ctx, n); err != nil {
			return fmt.Errorf("failed while re-creating peer %v with ASN %v: %w", n.Address, n.ASN, err)
		}
		return nil
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

	// apply the TCP-AO keychain changes that need to happen after the peer update
	if err := g.finishTCPAOUpdate(ctx, n, tcpAOUpdate); err != nil {
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
// If no such peer can be found, error is returned.
func (g *GoBGPServer) getExistingPeer(ctx context.Context, peerAddr netip.Addr, peerASN uint32) (*gobgp.Peer, error) {
	var res *gobgp.Peer
	addrFound := false
	fn := func(peer *gobgp.Peer) {
		pIP, err := netip.ParseAddr(peer.Conf.NeighborAddress)
		if err == nil && pIP == peerAddr {
			addrFound = true
			if peer.Conf.PeerAsn == peerASN {
				res = peer
			}
		}
	}

	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{Address: peerAddr.String()}, fn)
	if err != nil {
		return nil, fmt.Errorf("listing peers failed: %w", err)
	}
	if res == nil {
		if !addrFound {
			return nil, fmt.Errorf("%w with IP: %s", errPeerNotFound, peerAddr)
		}
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
	// the TCP-AO keychain (if any) can be deleted now that the peer no longer references it
	if err := g.deleteTCPAOKeychain(ctx, n.Address); err != nil {
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
	// Get all peers first
	var peerAddresses []string
	fn := func(peer *gobgp.Peer) {
		if peer != nil && peer.Conf != nil {
			peerAddresses = append(peerAddresses, peer.Conf.NeighborAddress)
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
