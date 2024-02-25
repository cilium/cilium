// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// AddNeighbor will add the CiliumBGPNeighbor to the gobgp.BgpServer, creating
// a BGP peering connection.
func (g *GoBGPServer) AddNeighbor(ctx context.Context, n types.NeighborRequest) error {
	peer, _, err := g.getPeerConfig(ctx, n, false)
	if err != nil {
		return err
	}
	peerReq := &gobgp.AddPeerRequest{
		Peer: peer,
	}
	if err = g.server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %s with ASN %d: %w", peer.Conf.NeighborAddress, peer.Conf.PeerAsn, err)
	}
	return nil
}

// UpdateNeighbor will update the existing CiliumBGPNeighbor in the gobgp.BgpServer.
func (g *GoBGPServer) UpdateNeighbor(ctx context.Context, n types.NeighborRequest) error {
	peer, needsHardReset, err := g.getPeerConfig(ctx, n, true)
	if err != nil {
		return err
	}

	// update peer config
	peerReq := &gobgp.UpdatePeerRequest{
		Peer: peer,
	}
	updateRes, err := g.server.UpdatePeer(ctx, peerReq)
	if err != nil {
		return fmt.Errorf("failed while updating peer %v:%v with ASN %v: %w", peer.Conf.NeighborAddress, peer.Transport.RemotePort, peer.Conf.PeerAsn, err)
	}

	// perform full / soft peer reset if necessary
	if needsHardReset || updateRes.NeedsSoftResetIn {
		g.logger.Infof("Resetting peer %s:%v (ASN %d) due to a config change", peer.Conf.NeighborAddress, peer.Transport.RemotePort, peer.Conf.PeerAsn)
		resetReq := &gobgp.ResetPeerRequest{
			Address:       peer.Conf.NeighborAddress,
			Communication: "Peer configuration changed",
		}
		if !needsHardReset {
			resetReq.Soft = true
			resetReq.Direction = gobgp.ResetPeerRequest_IN
		}
		if err = g.server.ResetPeer(ctx, resetReq); err != nil {
			return fmt.Errorf("failed while resetting peer %v:%v in ASN %v: %w", peer.Conf.NeighborAddress, peer.Transport.RemotePort, peer.Conf.PeerAsn, err)
		}
	}

	return nil
}

// convertBGPNeighborSAFI will convert a slice of CiliumBGPFamily to a slice of
// gobgp.AfiSafi.
//
// Our internal S/Afi types use the same integer values as the gobgp library,
// so we can simply cast our types into the corresponding gobgp types.
func convertBGPNeighborSAFI(fams []v2alpha1.CiliumBGPFamily) ([]*gobgp.AfiSafi, error) {
	if len(fams) == 0 {
		return defaultSafiAfi, nil
	}

	out := make([]*gobgp.AfiSafi, 0, len(fams))
	for _, fam := range fams {
		var safi types.Safi
		var afi types.Afi
		if err := safi.FromString(fam.Safi); err != nil {
			return out, fmt.Errorf("failed to parse Safi: %w", err)
		}
		if err := afi.FromString(fam.Afi); err != nil {
			return out, fmt.Errorf("failed to parse Afi: %w", err)
		}
		out = append(out, &gobgp.AfiSafi{
			Config: &gobgp.AfiSafiConfig{
				Family: &gobgp.Family{
					Afi:  gobgp.Family_Afi(afi),
					Safi: gobgp.Family_Safi(safi),
				},
			},
		})
	}
	return out, nil
}

func (g *GoBGPServer) getPeerConfig(ctx context.Context, n types.NeighborRequest, isUpdate bool) (peer *gobgp.Peer, needsReset bool, err error) {
	if n.Peer != nil {
		// Peer config is set when BGPv2 is enabled.
		return g.getPeerConfigV2(ctx, n, isUpdate)
	}

	return g.getPeerConfigV1(ctx, n, isUpdate)
}

// getPeerConfigV1 returns GoBGP Peer configuration for the provided CiliumBGPNeighbor.
func (g *GoBGPServer) getPeerConfigV1(ctx context.Context, n types.NeighborRequest, isUpdate bool) (peer *gobgp.Peer, needsReset bool, err error) {
	if n.Neighbor == nil {
		return peer, needsReset, fmt.Errorf("nil neighbor in NeighborRequest: %w", err)
	}

	// cilium neighbor uses prefix string, gobgp neighbor uses IP string, convert.
	prefix, err := netip.ParsePrefix(n.Neighbor.PeerAddress)
	if err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return peer, needsReset, fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerAddr := prefix.Addr()
	peerPort := uint32(*n.Neighbor.PeerPort)

	var existingPeer *gobgp.Peer
	peer, existingPeer, err = g.getPeer(ctx, peerAddr, uint32(n.Neighbor.PeerASN), isUpdate)
	if err != nil {
		return peer, needsReset, err
	}

	peer.AfiSafis, err = convertBGPNeighborSAFI(n.Neighbor.Families)
	if err != nil {
		return peer, needsReset, fmt.Errorf("failed to convert CiliumBGPNeighbor Families to gobgp AfiSafi: %w", err)
	}

	// set peer password
	peer.Conf.AuthPassword = n.Password

	// set peer transport, for local port we do not set it ( default 0 - unset )
	g.setPeerTransport(peer, existingPeer, peerAddr, peerPort, 0)

	// set peer ebgp multihop
	if n.Neighbor.EBGPMultihopTTL != nil {
		g.setPeerEBGPMultihopTTL(peer, uint32(n.Neighbor.PeerASN), uint32(*n.Neighbor.EBGPMultihopTTL))
	}

	// set peer timers
	g.setPeerTimers(peer, uint64(*n.Neighbor.ConnectRetryTimeSeconds), uint64(*n.Neighbor.HoldTimeSeconds), uint64(*n.Neighbor.KeepAliveTimeSeconds))

	// set peer graceful restart
	if n.Neighbor.GracefulRestart != nil && n.Neighbor.GracefulRestart.RestartTimeSeconds != nil {
		g.setPeerGracefulRestart(peer, uint32(*n.Neighbor.GracefulRestart.RestartTimeSeconds), n.Neighbor.GracefulRestart.Enabled)
	}

	if isUpdate {
		// In some cases, we want to perform full session reset on update even if GoBGP would not perform it.
		// An example of that is updating timer parameters that are negotiated during the session setup.
		// As we provide declarative API (CRD), we want this config to be applied on existing sessions
		// immediately, therefore we need full session reset.
		needsReset = existingPeer != nil &&
			(peer.Timers.Config.HoldTime != existingPeer.Timers.Config.HoldTime ||
				peer.Timers.Config.KeepaliveInterval != existingPeer.Timers.Config.KeepaliveInterval)
	}

	return peer, needsReset, err
}

// getPeerConfigV2 returns GoBGP Peer configuration for the provided CiliumBGPNodePeer and CiliumBGPPeerConfigSpec.
func (g *GoBGPServer) getPeerConfigV2(ctx context.Context, n types.NeighborRequest, isUpdate bool) (peer *gobgp.Peer, needsReset bool, err error) {
	if n.Peer == nil || n.PeerConfig == nil {
		return peer, needsReset, fmt.Errorf("nil peer config in NeighborRequest: %w", err)
	}

	if n.Peer.PeerASN == nil {
		// currently peer ASN is required.
		return peer, needsReset, fmt.Errorf("nil peer ASN")
	}

	if n.Peer.PeerAddress == nil {
		// currently peer address is required.
		return peer, needsReset, fmt.Errorf("nil peer address")
	}

	peerAddr, err := netip.ParseAddr(*n.Peer.PeerAddress)
	if err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return peer, needsReset, fmt.Errorf("failed to parse PeerAddress: %w", err)
	}

	localPort := uint32(*n.PeerConfig.Transport.LocalPort)
	peerPort := uint32(*n.PeerConfig.Transport.PeerPort)

	var existingPeer *gobgp.Peer
	peer, existingPeer, err = g.getPeer(ctx, peerAddr, uint32(*n.Peer.PeerASN), isUpdate)
	if err != nil {
		return peer, needsReset, err
	}

	// set address families
	var families []v2alpha1.CiliumBGPFamily
	for _, fam := range n.PeerConfig.Families {
		families = append(families, fam.CiliumBGPFamily)
	}

	peer.AfiSafis, err = convertBGPNeighborSAFI(families)
	if err != nil {
		return peer, needsReset, fmt.Errorf("failed to convert CiliumBGPNeighbor Families to gobgp AfiSafi: %w", err)
	}

	// set peer password
	peer.Conf.AuthPassword = n.Password

	// set peer transport
	g.setPeerTransport(peer, existingPeer, peerAddr, peerPort, localPort)

	// set peer ebgp multihop
	if n.PeerConfig.EBGPMultihop != nil {
		g.setPeerEBGPMultihopTTL(peer, uint32(*n.Peer.PeerASN), uint32(*n.PeerConfig.EBGPMultihop))
	}

	// set peer timers
	if n.PeerConfig.Timers != nil {
		g.setPeerTimers(peer, uint64(*n.PeerConfig.Timers.ConnectRetryTimeSeconds), uint64(*n.PeerConfig.Timers.HoldTimeSeconds), uint64(*n.PeerConfig.Timers.KeepAliveTimeSeconds))
	}

	// set peer graceful restart
	if n.PeerConfig.GracefulRestart != nil && n.PeerConfig.GracefulRestart.RestartTimeSeconds != nil {
		g.setPeerGracefulRestart(peer, uint32(*n.PeerConfig.GracefulRestart.RestartTimeSeconds), n.PeerConfig.GracefulRestart.Enabled)
	}

	if isUpdate {
		// In some cases, we want to perform full session reset on update even if GoBGP would not perform it.
		// An example of that is updating timer parameters that are negotiated during the session setup.
		// As we provide declarative API (CRD), we want this config to be applied on existing sessions
		// immediately, therefore we need full session reset.
		needsReset = existingPeer != nil &&
			(peer.Timers.Config.HoldTime != existingPeer.Timers.Config.HoldTime ||
				peer.Timers.Config.KeepaliveInterval != existingPeer.Timers.Config.KeepaliveInterval)
	}

	return peer, needsReset, nil
}

func (g *GoBGPServer) setPeerTransport(peer, existingPeer *gobgp.Peer, peerAddr netip.Addr, peerPort, localPort uint32) {
	if existingPeer != nil {
		peer.Transport = existingPeer.Transport
	} else {
		peer.Transport = &gobgp.Transport{}
	}

	if localPort > 0 {
		peer.Transport.LocalPort = localPort
	}

	if peerPort > 0 {
		peer.Transport.RemotePort = peerPort
	}

	if peerAddr.Is4() {
		peer.Transport.LocalAddress = wildcardIPv4Addr
	} else {
		peer.Transport.LocalAddress = wildcardIPv6Addr
	}
}

func (g *GoBGPServer) setPeerEBGPMultihopTTL(peer *gobgp.Peer, peerASN, ebgpMultihopTTL uint32) {
	if g.asn != peerASN && ebgpMultihopTTL > 1 {
		peer.EbgpMultihop = &gobgp.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: ebgpMultihopTTL,
		}
	}
}

func (g *GoBGPServer) setPeerTimers(peer *gobgp.Peer, connect, hold, keepalive uint64) {
	if peer.Timers == nil {
		peer.Timers = &gobgp.Timers{}
	}
	peer.Timers.Config = &gobgp.TimersConfig{
		ConnectRetry:           connect,
		HoldTime:               hold,
		KeepaliveInterval:      keepalive,
		IdleHoldTimeAfterReset: idleHoldTimeAfterResetSeconds,
	}
}

func (g *GoBGPServer) setPeerGracefulRestart(peer *gobgp.Peer, restartTime uint32, enabled bool) {
	if peer.GracefulRestart == nil {
		peer.GracefulRestart = &gobgp.GracefulRestart{}
	}

	if enabled {
		peer.GracefulRestart.Enabled = true
		peer.GracefulRestart.RestartTime = restartTime
		peer.GracefulRestart.NotificationEnabled = true
		peer.GracefulRestart.LocalRestarting = true
	}

	for _, afiConf := range peer.AfiSafis {
		if afiConf.MpGracefulRestart == nil {
			afiConf.MpGracefulRestart = &gobgp.MpGracefulRestart{}
		}
		afiConf.MpGracefulRestart.Config = &gobgp.MpGracefulRestartConfig{
			Enabled: peer.GracefulRestart.Enabled,
		}
	}
}

func (g *GoBGPServer) getPeer(ctx context.Context, peerAddr netip.Addr, peerASN uint32, isUpdate bool) (peer, existingPeer *gobgp.Peer, err error) {
	if isUpdate {
		// If this is an update, try retrieving the existing Peer.
		// This is necessary as many Peer fields are defaulted internally in GoBGP,
		// and if they were not set, the update would always cause BGP peer reset.
		// This will not fail if the peer is not found for whatever reason.
		existingPeer, err = g.getExistingPeer(ctx, peerAddr, peerASN)
		if err != nil {
			return peer, existingPeer, fmt.Errorf("failed retrieving peer: %w", err)
		}
		// use only necessary parts of the existing peer struct
		peer = &gobgp.Peer{
			Conf:      existingPeer.Conf,
			Transport: existingPeer.Transport,
		}
	} else {
		// Create a new peer
		peer = &gobgp.Peer{
			Conf: &gobgp.PeerConf{
				NeighborAddress: peerAddr.String(),
				PeerAsn:         peerASN,
			},
		}
	}
	return peer, existingPeer, nil
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
func (g *GoBGPServer) RemoveNeighbor(ctx context.Context, n types.NeighborRequest) error {
	var address string
	if n.Peer != nil {
		// for BGPv2 n.Peer will set, n.Neighbor will not.
		addr, err := netip.ParseAddr(*n.Peer.PeerAddress)
		if err != nil {
			return fmt.Errorf("failed to parse PeerAddress: %w", err)
		}
		address = addr.String()

	} else {
		// cilium neighbor uses prefix string, gobgp neighbor uses IP string, convert.
		prefix, err := netip.ParsePrefix(n.Neighbor.PeerAddress)
		if err != nil {
			// unlikely, we validate this on CR write to k8s api.
			return fmt.Errorf("failed to parse PeerAddress: %w", err)
		}

		address = prefix.Addr().String()
	}

	peerReq := &gobgp.DeletePeerRequest{
		Address: address,
	}
	if err := g.server.DeletePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.Neighbor.PeerAddress, n.Neighbor.PeerASN, err)
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
