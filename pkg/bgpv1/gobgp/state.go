// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/time"
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

		if peer.Transport != nil {
			peerState.PeerPort = int64(peer.Transport.RemotePort)
		}

		if peer.Conf != nil {
			peerState.LocalAsn = int64(peer.Conf.LocalAsn)
			peerState.PeerAddress = peer.Conf.NeighborAddress
			peerState.PeerAsn = int64(peer.Conf.PeerAsn)
			peerState.TCPPasswordEnabled = peer.Conf.AuthPassword != ""
		}

		if peer.State != nil {
			if peer.Conf.PeerAsn == 0 { // if peerAsn is not set, use peer state peerAsn
				peerState.PeerAsn = int64(peer.State.PeerAsn)
			}

			peerState.SessionState = toAgentSessionState(peer.State.SessionState).String()

			// Uptime is time since session got established.
			// It is calculated by difference in time from uptime timestamp till now.
			if peer.State.SessionState == gobgp.PeerState_ESTABLISHED && peer.Timers != nil && peer.Timers.State != nil {
				peerState.UptimeNanoseconds = int64(time.Since(peer.Timers.State.Uptime.AsTime()))
			}
		}

		for _, afiSafi := range peer.AfiSafis {
			if afiSafi.State == nil {
				continue
			}
			peerState.Families = append(peerState.Families, toAgentAfiSafiState(afiSafi.State))
		}

		if peer.EbgpMultihop != nil && peer.EbgpMultihop.Enabled {
			peerState.EbgpMultihopTTL = int64(peer.EbgpMultihop.MultihopTtl)
		} else {
			peerState.EbgpMultihopTTL = int64(v2.DefaultBGPEBGPMultihopTTL) // defaults to 1 if not enabled
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

		peerState.GracefulRestart = &models.BgpGracefulRestart{}
		if peer.GracefulRestart != nil {
			peerState.GracefulRestart.Enabled = peer.GracefulRestart.Enabled
			peerState.GracefulRestart.RestartTimeSeconds = int64(peer.GracefulRestart.RestartTime)
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

// GetRoutes retrieves routes from the RIB of underlying router
func (g *GoBGPServer) GetRoutes(ctx context.Context, r *types.GetRoutesRequest) (*types.GetRoutesResponse, error) {
	errs := []error{}
	var routes []*types.Route

	fn := func(destination *gobgp.Destination) {
		paths, err := ToAgentPaths(destination.Paths)
		if err != nil {
			errs = append(errs, err)
			return
		}
		routes = append(routes, &types.Route{
			Prefix: destination.Prefix,
			Paths:  paths,
		})
	}

	tt, err := toGoBGPTableType(r.TableType)
	if err != nil {
		return nil, fmt.Errorf("invalid table type: %w", err)
	}

	family := &gobgp.Family{
		Afi:  gobgp.Family_Afi(r.Family.Afi),
		Safi: gobgp.Family_Safi(r.Family.Safi),
	}

	var neighbor string
	if r.Neighbor.IsValid() {
		neighbor = r.Neighbor.String()
	}

	req := &gobgp.ListPathRequest{
		TableType: tt,
		Family:    family,
		Name:      neighbor,
	}

	if err := g.server.ListPath(ctx, req, fn); err != nil {
		return nil, err
	}

	return &types.GetRoutesResponse{
		Routes: routes,
	}, nil
}

// GetRoutePolicies retrieves route policies from the underlying router
func (g *GoBGPServer) GetRoutePolicies(ctx context.Context) (*types.GetRoutePoliciesResponse, error) {
	// list defined sets into a map for later use
	definedSets := make(map[string]*gobgp.DefinedSet)
	err := g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_NEIGHBOR}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing neighbor defined sets: %w", err)
	}
	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_PREFIX}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing prefix defined sets: %w", err)
	}

	// list policy assignments into a map for later use
	assignments := make(map[string]*gobgp.PolicyAssignment)
	err = g.server.ListPolicyAssignment(ctx, &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
		for _, p := range a.Policies {
			assignments[p.Name] = a
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing policy assignments: %w", err)
	}

	// list & convert policies
	var policies []*types.RoutePolicy
	err = g.server.ListPolicy(ctx, &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
		// process only assigned policies
		if assignment, exists := assignments[p.Name]; exists {
			policies = append(policies, toAgentPolicy(p, definedSets, assignment))
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing route policies: %w", err)
	}

	return &types.GetRoutePoliciesResponse{
		Policies: policies,
	}, nil
}
