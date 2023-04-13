// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	apb "google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/bgpv1/types"
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
	logger := NewServerLogger(log.Logger, params.Global.ASN)

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
	// cilium neighbor uses CIDR string, gobgp neighbor uses IP string, convert.
	var ip net.IP
	var err error
	if ip, _, err = net.ParseCIDR(n.Neighbor.PeerAddress); err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerReq := &gobgp.AddPeerRequest{
		Peer: &gobgp.Peer{
			Conf: &gobgp.PeerConf{
				NeighborAddress: ip.String(),
				PeerAsn:         uint32(n.Neighbor.PeerASN),
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
		},
	}
	if err = g.server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %v %v: %w", n.Neighbor.PeerAddress, n.Neighbor.PeerASN, err)
	}
	return nil
}

// RemoveNeighbor will remove the CiliumBGPNeighbor from the gobgp.BgpServer,
// disconnecting the BGP peering connection.
func (g *GoBGPServer) RemoveNeighbor(ctx context.Context, n types.NeighborRequest) error {
	// cilium neighbor uses CIDR string, gobgp neighbor uses IP string, convert.
	var ip net.IP
	var err error
	if ip, _, err = net.ParseCIDR(n.Neighbor.PeerAddress); err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerReq := &gobgp.DeletePeerRequest{
		Address: ip.String(),
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
	ip := p.Advert.Net

	origin, _ := apb.New(&gobgp.OriginAttribute{
		Origin: 0,
	})
	switch {
	case ip.IP.To4() != nil:
		prefixLen, _ := ip.Mask.Size()
		nlri, _ := apb.New(&gobgp.IPAddressPrefix{
			PrefixLen: uint32(prefixLen),
			Prefix:    ip.IP.String(),
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
	case ip.IP.To16() != nil:
		prefixLen, _ := ip.Mask.Size()
		nlri, _ := apb.New(&gobgp.IPAddressPrefix{
			PrefixLen: uint32(prefixLen),
			Prefix:    ip.IP.String(),
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
		return types.PathResponse{}, fmt.Errorf("provided IP returned nil for both IPv4 and IPv6 lengths: %v", len(ip.IP))
	}
	if err != nil {
		return types.PathResponse{}, err
	}
	return types.PathResponse{
		Advert: types.Advertisement{
			Net:           ip,
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
