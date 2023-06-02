// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"

	gobgp "github.com/osrg/gobgp/v3/api"
)

// GetBgp returns bgp global configuration from gobgp server
func (g *GoBGPServer) GetBGP(ctx context.Context) (types.GetBGPResponse, error) {
	bgpConfig, err := g.server.GetBgp(ctx, &gobgp.GetBgpRequest{})
	if err != nil {
		return types.GetBGPResponse{}, err
	}

	if bgpConfig.Global == nil {
		return types.GetBGPResponse{}, fmt.Errorf("gobgp returned nil config")
	}

	res := types.BGPGlobal{
		ASN:        bgpConfig.Global.Asn,
		RouterID:   bgpConfig.Global.RouterId,
		ListenPort: bgpConfig.Global.ListenPort,
	}
	if bgpConfig.Global.RouteSelectionOptions != nil {
		res.RouteSelectionOptions = &types.RouteSelectionOptions{
			AdvertiseInactiveRoutes: bgpConfig.Global.RouteSelectionOptions.AdvertiseInactiveRoutes,
		}
	}

	return types.GetBGPResponse{
		Global: res,
	}, nil
}

// GetPeerState invokes goBGP ListPeer API to get current peering state.
func (g *GoBGPServer) GetPeerState(ctx context.Context) (types.GetPeerStateResponse, error) {
	var data []*models.BgpPeer
	fn := func(peer *gobgp.Peer) {
		if peer == nil {
			return
		}

		peerState := &models.BgpPeer{}

		if peer.Conf != nil {
			peerState.LocalAsn = int64(peer.Conf.LocalAsn)
			peerState.PeerAddress = peer.Conf.NeighborAddress
			peerState.PeerAsn = int64(peer.Conf.PeerAsn)
		}

		if peer.State != nil {
			peerState.SessionState = toAgentSessionState(peer.State.SessionState).String()

			// Uptime is time since session got established.
			// It is calculated by difference in time from uptime timestamp till now.
			if peer.State.SessionState == gobgp.PeerState_ESTABLISHED && peer.Timers != nil && peer.Timers.State != nil {
				peerState.UptimeNanoseconds = int64(time.Now().Sub(peer.Timers.State.Uptime.AsTime()))
			}
		}

		for _, afiSafi := range peer.AfiSafis {
			if afiSafi.State == nil {
				continue
			}
			peerState.Families = append(peerState.Families, toAgentAfiSafiState(afiSafi.State))
		}

		if peer.Timers != nil {
			tConfig := peer.Timers.Config
			tState := peer.Timers.State
			if tConfig != nil {
				peerState.ConnectRetryTimeSeconds = int64(tConfig.ConnectRetry)
				peerState.ConfiguredHoldTimeSeconds = int64(tConfig.HoldTime)
				peerState.ConfiguredKeepAliveTimeSeconds = int64(tConfig.KeepaliveInterval)
			}
			if tState != nil {
				if tState.NegotiatedHoldTime != 0 {
					peerState.AppliedHoldTimeSeconds = int64(tState.NegotiatedHoldTime)
				}
				if tState.KeepaliveInterval != 0 {
					peerState.AppliedKeepAliveTimeSeconds = int64(tState.KeepaliveInterval)
				}
			}
		}

		data = append(data, peerState)
	}

	// API to get peering list from gobgp, enableAdvertised is set to true to get count of
	// advertised routes.
	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{EnableAdvertised: true}, fn)
	if err != nil {
		return types.GetPeerStateResponse{}, err
	}

	return types.GetPeerStateResponse{
		Peers: data,
	}, nil
}

// toAgentAfiSafiState translates gobgp structures to cilium bgp models.
func toAgentAfiSafiState(state *gobgp.AfiSafiState) *models.BgpPeerFamilies {
	res := &models.BgpPeerFamilies{}

	if state.Family != nil {
		res.Afi = toAgentAfi(state.Family.Afi).String()
		res.Safi = toAgentSafi(state.Family.Safi).String()
	}

	res.Received = int64(state.Received)
	res.Accepted = int64(state.Accepted)
	res.Advertised = int64(state.Advertised)

	return res
}

// toAgentSessionState translates gobgp session state to cilium bgp session state.
func toAgentSessionState(s gobgp.PeerState_SessionState) types.SessionState {
	switch s {
	case gobgp.PeerState_UNKNOWN:
		return types.SessionUnknown
	case gobgp.PeerState_IDLE:
		return types.SessionIdle
	case gobgp.PeerState_CONNECT:
		return types.SessionConnect
	case gobgp.PeerState_ACTIVE:
		return types.SessionActive
	case gobgp.PeerState_OPENSENT:
		return types.SessionOpenSent
	case gobgp.PeerState_OPENCONFIRM:
		return types.SessionOpenConfirm
	case gobgp.PeerState_ESTABLISHED:
		return types.SessionEstablished
	default:
		return types.SessionUnknown
	}
}

// toAgentAfi translates gobgp AFI to cilium bgp AFI.
func toAgentAfi(a gobgp.Family_Afi) types.Afi {
	switch a {
	case gobgp.Family_AFI_UNKNOWN:
		return types.AfiUnknown
	case gobgp.Family_AFI_IP:
		return types.AfiIPv4
	case gobgp.Family_AFI_IP6:
		return types.AfiIPv6
	case gobgp.Family_AFI_L2VPN:
		return types.AfiL2VPN
	case gobgp.Family_AFI_LS:
		return types.AfiLS
	case gobgp.Family_AFI_OPAQUE:
		return types.AfiOpaque
	default:
		return types.AfiUnknown
	}
}

func toAgentSafi(s gobgp.Family_Safi) types.Safi {
	switch s {
	case gobgp.Family_SAFI_UNKNOWN:
		return types.SafiUnknown
	case gobgp.Family_SAFI_UNICAST:
		return types.SafiUnicast
	case gobgp.Family_SAFI_MULTICAST:
		return types.SafiMulticast
	case gobgp.Family_SAFI_MPLS_LABEL:
		return types.SafiMplsLabel
	case gobgp.Family_SAFI_ENCAPSULATION:
		return types.SafiEncapsulation
	case gobgp.Family_SAFI_VPLS:
		return types.SafiVpls
	case gobgp.Family_SAFI_EVPN:
		return types.SafiEvpn
	case gobgp.Family_SAFI_LS:
		return types.SafiLs
	case gobgp.Family_SAFI_SR_POLICY:
		return types.SafiSrPolicy
	case gobgp.Family_SAFI_MUP:
		return types.SafiMup
	case gobgp.Family_SAFI_MPLS_VPN:
		return types.SafiMplsVpn
	case gobgp.Family_SAFI_MPLS_VPN_MULTICAST:
		return types.SafiMplsVpnMulticast
	case gobgp.Family_SAFI_ROUTE_TARGET_CONSTRAINTS:
		return types.SafiRouteTargetConstraints
	case gobgp.Family_SAFI_FLOW_SPEC_UNICAST:
		return types.SafiFlowSpecUnicast
	case gobgp.Family_SAFI_FLOW_SPEC_VPN:
		return types.SafiFlowSpecVpn
	case gobgp.Family_SAFI_KEY_VALUE:
		return types.SafiKeyValue
	default:
		return types.SafiUnknown
	}
}
