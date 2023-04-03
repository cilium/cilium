// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"time"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
)

// GetPeerState invokes goBGP ListPeer API to get current peering state.
func (sc *ServerWithConfig) GetPeerState(ctx context.Context) ([]*models.BgpPeer, error) {
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
			// Time is rounded to second precision.
			if peer.State.SessionState == gobgp.PeerState_ESTABLISHED && peer.Timers != nil && peer.Timers.State != nil {
				peerState.UptimeNanoseconds = int64(time.Now().Sub(peer.Timers.State.Uptime.AsTime()).Round(time.Second))
			}
		}

		for _, afiSafi := range peer.AfiSafis {
			if afiSafi.State == nil {
				continue
			}
			peerState.Families = append(peerState.Families, toAgentAfiSafiState(afiSafi.State))
		}

		data = append(data, peerState)
	}

	// API to get peering list from gobgp, enableAdvertised is set to true to get count of
	// advertised routes.
	err := sc.Server.ListPeer(ctx, &gobgp.ListPeerRequest{EnableAdvertised: true}, fn)
	if err != nil {
		return nil, err
	}

	return data, nil
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
func toAgentSessionState(s gobgp.PeerState_SessionState) agent.SessionState {
	switch s {
	case gobgp.PeerState_UNKNOWN:
		return agent.SessionUnknown
	case gobgp.PeerState_IDLE:
		return agent.SessionIdle
	case gobgp.PeerState_CONNECT:
		return agent.SessionConnect
	case gobgp.PeerState_ACTIVE:
		return agent.SessionActive
	case gobgp.PeerState_OPENSENT:
		return agent.SessionOpenSent
	case gobgp.PeerState_OPENCONFIRM:
		return agent.SessionOpenConfirm
	case gobgp.PeerState_ESTABLISHED:
		return agent.SessionEstablished
	default:
		return agent.SessionUnknown
	}
}

// toAgentAfi translates gobgp AFI to cilium bgp AFI.
func toAgentAfi(a gobgp.Family_Afi) agent.Afi {
	switch a {
	case gobgp.Family_AFI_UNKNOWN:
		return agent.AfiUnknown
	case gobgp.Family_AFI_IP:
		return agent.AfiIPv4
	case gobgp.Family_AFI_IP6:
		return agent.AfiIPv6
	case gobgp.Family_AFI_L2VPN:
		return agent.AfiL2VPN
	case gobgp.Family_AFI_LS:
		return agent.AfiLS
	case gobgp.Family_AFI_OPAQUE:
		return agent.AfiOpaque
	default:
		return agent.AfiUnknown
	}
}

func toAgentSafi(s gobgp.Family_Safi) agent.Safi {
	switch s {
	case gobgp.Family_SAFI_UNKNOWN:
		return agent.SafiUnknown
	case gobgp.Family_SAFI_UNICAST:
		return agent.SafiUnicast
	case gobgp.Family_SAFI_MULTICAST:
		return agent.SafiMulticast
	case gobgp.Family_SAFI_MPLS_LABEL:
		return agent.SafiMplsLabel
	case gobgp.Family_SAFI_ENCAPSULATION:
		return agent.SafiEncapsulation
	case gobgp.Family_SAFI_VPLS:
		return agent.SafiVpls
	case gobgp.Family_SAFI_EVPN:
		return agent.SafiEvpn
	case gobgp.Family_SAFI_LS:
		return agent.SafiLs
	case gobgp.Family_SAFI_SR_POLICY:
		return agent.SafiSrPolicy
	case gobgp.Family_SAFI_MUP:
		return agent.SafiMup
	case gobgp.Family_SAFI_MPLS_VPN:
		return agent.SafiMplsVpn
	case gobgp.Family_SAFI_MPLS_VPN_MULTICAST:
		return agent.SafiMplsVpnMulticast
	case gobgp.Family_SAFI_ROUTE_TARGET_CONSTRAINTS:
		return agent.SafiRouteTargetConstraints
	case gobgp.Family_SAFI_FLOW_SPEC_UNICAST:
		return agent.SafiFlowSpecUnicast
	case gobgp.Family_SAFI_FLOW_SPEC_VPN:
		return agent.SafiFlowSpecVpn
	case gobgp.Family_SAFI_KEY_VALUE:
		return agent.SafiKeyValue
	default:
		return agent.SafiUnknown
	}
}
