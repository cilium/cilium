// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	apb "google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	wildcardIPv4Addr = "0.0.0.0"
	wildcardIPv6Addr = "::"
)

var (
	// GoBGPIPv6Family is a read-only pointer to a gobgp.Family structure
	// representing IPv6 address family.
	GoBGPIPv6Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP6,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
	// GoBGPIPv4Family is a read-only pointer to a gobgp.Family structure
	// representing IPv4 address family.
	GoBGPIPv4Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
)

// GoBGPServer is wrapper on top of go bgp server implementation
type GoBGPServer struct {
	logger *logrus.Entry

	// asn is local AS number
	asn uint32

	// a gobgp backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	server *server.BgpServer
}

// NewGoBGPServerWithConfig returns instance of go bgp router wrapper.
func NewGoBGPServerWithConfig(ctx context.Context, log *logrus.Entry, params types.ServerParameters) (types.Router, error) {
	logger := NewServerLogger(log.Logger, LogParams{
		AS:        params.Global.ASN,
		Component: "gobgp.BgpServerInstance",
		SubSys:    "bgp-control-plane",
	})

	s := server.NewBgpServer(server.LoggerOption(logger))
	go s.Serve()

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        params.Global.ASN,
			RouterId:   params.Global.RouterID,
			ListenPort: params.Global.ListenPort,
		},
	}

	if params.Global.RouteSelectionOptions != nil {
		startReq.Global.RouteSelectionOptions = &gobgp.RouteSelectionOptionsConfig{
			AdvertiseInactiveRoutes: params.Global.RouteSelectionOptions.AdvertiseInactiveRoutes,
		}
	}

	if err := s.StartBgp(ctx, startReq); err != nil {
		return nil, fmt.Errorf("failed starting BGP server: %w", err)
	}

	// will log out any peer changes.
	watchRequest := &gobgp.WatchEventRequest{
		Peer: &gobgp.WatchEventRequest_Peer{},
	}
	err := s.WatchEvent(ctx, watchRequest, func(r *gobgp.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Type == gobgp.WatchEventResponse_PeerEvent_STATE {
			logger.l.Info(p)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure logging for virtual router with local-asn %v: %w", startReq.Global.Asn, err)
	}

	return &GoBGPServer{
		logger: log,
		asn:    params.Global.ASN,
		server: s,
	}, nil
}

// AddNeighbor will add the CiliumBGPNeighbor to the gobgp.BgpServer, creating
// a BGP peering connection.
func (g *GoBGPServer) AddNeighbor(ctx context.Context, n types.NeighborRequest) error {
	peer, err := g.getPeerConfig(ctx, n.Neighbor, false)
	if err != nil {
		return err
	}
	peerReq := &gobgp.AddPeerRequest{
		Peer: peer,
	}
	if err = g.server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %v %v: %w", n.Neighbor.PeerAddress, n.Neighbor.PeerASN, err)
	}
	return nil
}

// UpdateNeighbor will update the existing CiliumBGPNeighbor in the gobgp.BgpServer.
func (g *GoBGPServer) UpdateNeighbor(ctx context.Context, n types.NeighborRequest) error {
	peer, err := g.getPeerConfig(ctx, n.Neighbor, true)
	if err != nil {
		return err
	}
	peerReq := &gobgp.UpdatePeerRequest{
		DoSoftResetIn: true, // should perform soft reset only if needed
		Peer:          peer,
	}
	if _, err = g.server.UpdatePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while updating peer %v %v: %w", n.Neighbor.PeerAddress, n.Neighbor.PeerASN, err)
	}
	return nil
}

// getPeerConfig returns GoBGP Peer configuration for the provided CiliumBGPNeighbor.
func (g *GoBGPServer) getPeerConfig(ctx context.Context, n *v2alpha1api.CiliumBGPNeighbor, isUpdate bool) (*gobgp.Peer, error) {
	// cilium neighbor uses prefix string, gobgp neighbor uses IP string, convert.
	prefix, err := netip.ParsePrefix(n.PeerAddress)
	if err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return nil, fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerAddr := prefix.Addr()

	var peer *gobgp.Peer
	if isUpdate {
		// If this is an update, try retrieving the existing Peer.
		// This is necessary as many Peer fields are defaulted internally in GoBGP,
		// and if they were not set, the update would always cause BGP peer reset.
		// This will not fail if the peer is not found for whatever reason.
		existingPeer, err := g.getExistingPeer(ctx, peerAddr, uint32(n.PeerASN))
		if err != nil {
			return nil, fmt.Errorf("failed retrieving peer: %w", err)
		}
		// use only necessary parts of the existing peer struct
		peer = &gobgp.Peer{
			Conf:     existingPeer.Conf,
			AfiSafis: existingPeer.AfiSafis,
		}
	} else {
		// Create a new peer
		peer = &gobgp.Peer{
			Conf: &gobgp.PeerConf{
				NeighborAddress: peerAddr.String(),
				PeerAsn:         uint32(n.PeerASN),
			},
			// tells the peer we are capable of unicast IPv4 and IPv6
			// advertisements.
			AfiSafis: []*gobgp.AfiSafi{
				{
					Config: &gobgp.AfiSafiConfig{
						Family: GoBGPIPv4Family,
					},
				},
				{
					Config: &gobgp.AfiSafiConfig{
						Family: GoBGPIPv6Family,
					},
				},
			},
		}
	}

	// As GoBGP defaulting of peer's Transport.LocalAddress follows different paths
	// when calling AddPeer / UpdatePeer / ListPeer, we set it explicitly to a wildcard address
	// based on peer's address family, to not cause unnecessary connection resets upon update.
	if peerAddr.Is4() {
		peer.Transport = &gobgp.Transport{LocalAddress: wildcardIPv4Addr}
	} else {
		peer.Transport = &gobgp.Transport{LocalAddress: wildcardIPv6Addr}
	}

	if peer.Timers == nil {
		peer.Timers = &gobgp.Timers{}
	}
	peer.Timers.Config = &gobgp.TimersConfig{
		// If any of the timers is not set (zero), it will be defaulted at the gobgp level.
		// However, they should be already defaulted at this point.
		ConnectRetry:      uint64(n.ConnectRetryTime.Round(time.Second).Seconds()),
		HoldTime:          uint64(n.HoldTime.Round(time.Second).Seconds()),
		KeepaliveInterval: uint64(n.KeepAliveTime.Round(time.Second).Seconds()),
	}
	return peer, nil
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

// RemoveNeighbor will remove the CiliumBGPNeighbor from the gobgp.BgpServer,
// disconnecting the BGP peering connection.
func (g *GoBGPServer) RemoveNeighbor(ctx context.Context, n types.NeighborRequest) error {
	// cilium neighbor uses prefix string, gobgp neighbor uses IP string, convert.
	prefix, err := netip.ParsePrefix(n.Neighbor.PeerAddress)
	if err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerReq := &gobgp.DeletePeerRequest{
		Address: prefix.Addr().String(),
	}
	if err := g.server.DeletePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.Neighbor.PeerAddress, n.Neighbor.PeerASN, err)
	}
	return nil
}

// AdvertisePath will advertise the provided IP network to any existing and all
// subsequently added Neighbors currently peered with this BgpServer.
//
// `ip` can be an ipv4 or ipv6 and this method will handle the differences
// between MP BGP and BGP.
//
// It is an error to advertise an IPv6 path when no IPv6 address is configured
// on this Cilium node, selfsame for IPv4.
//
// Nexthop of the path will always set to "0.0.0.0" in IPv4 and "::" in IPv6, so
// that GoBGP selects appropriate actual nexthop address and advertise it.
//
// An Advertisement is returned which may be passed to WithdrawPath to remove
// this Advertisement.
func (g *GoBGPServer) AdvertisePath(ctx context.Context, p types.PathRequest) (types.PathResponse, error) {
	var err error
	var path *gobgp.Path
	var resp *gobgp.AddPathResponse
	prefix := p.Advert.Prefix

	origin, _ := apb.New(&gobgp.OriginAttribute{
		Origin: 0,
	})
	switch {
	case prefix.Addr().Is4():
		nlri, _ := apb.New(&gobgp.IPAddressPrefix{
			PrefixLen: uint32(prefix.Bits()),
			Prefix:    prefix.Addr().String(),
		})
		// Currently, we only support advertising locally originated paths (the paths generated in Cilium
		// node itself, not the paths received from another BGP Peer or redistributed from another routing
		// protocol. In this case, the nexthop address should be the address used for peering. That means
		// the nexthop address can be changed depending on the neighbor.
		//
		// For example, when the Cilium node is connected to two subnets 10.0.0.0/24 and 10.0.1.0/24 with
		// local address 10.0.0.1 and 10.0.1.1 respectively, the nexthop should be advertised for 10.0.0.0/24
		// peers is 10.0.0.1. On the other hand, we should advertise 10.0.1.1 as a nexthop for 10.0.1.0/24.
		//
		// Fortunately, GoBGP takes care of resolving appropriate nexthop address for each peers when we
		// specify an zero IP address (0.0.0.0 for IPv4 and :: for IPv6). So, we can just rely on that.
		//
		// References:
		// - RFC4271 Section 5.1.3 (NEXT_HOP)
		// - RFC4760 Section 3 (Multiprotocol Reachable NLRI - MP_REACH_NLRI (Type Code 14))
		nextHop, _ := apb.New(&gobgp.NextHopAttribute{
			NextHop: "0.0.0.0",
		})
		path = &gobgp.Path{
			Family: GoBGPIPv4Family,
			Nlri:   nlri,
			Pattrs: []*apb.Any{nextHop, origin},
		}
		resp, err = g.server.AddPath(ctx, &gobgp.AddPathRequest{
			Path: path,
		})
	case prefix.Addr().Is6():
		nlri, _ := apb.New(&gobgp.IPAddressPrefix{
			PrefixLen: uint32(prefix.Bits()),
			Prefix:    prefix.Addr().String(),
		})
		nlriAttrs, _ := apb.New(&gobgp.MpReachNLRIAttribute{ // MP BGP NLRI
			Family: GoBGPIPv6Family,
			// See the above explanation for IPv4
			NextHops: []string{"::"},
			Nlris:    []*apb.Any{nlri},
		})
		path = &gobgp.Path{
			Family: GoBGPIPv6Family,
			Nlri:   nlri,
			Pattrs: []*apb.Any{nlriAttrs, origin},
		}
		resp, err = g.server.AddPath(ctx, &gobgp.AddPathRequest{
			Path: path,
		})
	default:
		return types.PathResponse{}, fmt.Errorf("unknown address family for prefix %s", prefix.String())
	}
	if err != nil {
		return types.PathResponse{}, err
	}
	return types.PathResponse{
		Advert: types.Advertisement{
			Prefix:        prefix,
			GoBGPPathUUID: resp.Uuid,
		},
	}, err
}

// WithdrawPath withdraws an Advertisement produced by AdvertisePath from this
// BgpServer.
func (g *GoBGPServer) WithdrawPath(ctx context.Context, p types.PathRequest) error {
	err := g.server.DeletePath(ctx, &gobgp.DeletePathRequest{
		Uuid: p.Advert.GoBGPPathUUID,
	})
	return err
}

// Stop closes gobgp server
func (g *GoBGPServer) Stop() {
	if g.server != nil {
		g.server.Stop()
	}
}
